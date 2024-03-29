/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"github.com/eplightning/xds-servicelb/internal"
	"github.com/eplightning/xds-servicelb/internal/graph"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/net"
	"net/netip"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sort"
	"time"
)

const (
	proxyProtocolAnnotation = "xds-servicelb.eplight.org/use-proxy-protocol"
	idleTimeoutAnnotation   = "xds-servicelb.eplight.org/idle-timeout"
)

var (
	noValidNodeAddressError = errors.New("no valid node address found")
)

// ServiceReconciler reconciles a Service object
type ServiceReconciler struct {
	client.Client
	scheme   *runtime.Scheme
	graph    *graph.ServiceGraph
	config   *internal.Config
	recorder record.EventRecorder
}

func NewServiceReconciler(
	c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder, graph *graph.ServiceGraph, config *internal.Config,
) *ServiceReconciler {
	return &ServiceReconciler{
		Client:   c,
		scheme:   scheme,
		graph:    graph,
		config:   config,
		recorder: recorder,
	}
}

//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=core,resources=services/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core,resources=services/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if k8serrors.IsNotFound(err) {
			r.graph.RemoveService(req.NamespacedName)
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !r.shouldManage(&svc) {
		return ctrl.Result{}, nil
	}

	ports := r.getServicePorts(&svc)
	for _, port := range ports {
		if r.graph.Conflicts(req.NamespacedName, port) {
			r.recorder.Eventf(&svc, "Warning", "Conflict", "Service could not be allocated due to a conflicting port %v", port.String())

			return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
		}
	}

	data, err := r.buildServiceData(ctx, &svc, ports)
	if err != nil {
		return ctrl.Result{}, err
	}

	r.graph.UpdateService(req.NamespacedName, data)

	if err := r.updateStatus(ctx, &svc); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(r.findServiceForEndpoint)).
		Complete(r)
}

func (r *ServiceReconciler) buildEndpoints(ctx context.Context, svc *corev1.Service, port graph.ServicePort) ([]graph.ServiceEndpoint, error) {
	var svcPort *corev1.ServicePort
	for _, sp := range svc.Spec.Ports {
		if sp.Port == port.Port && string(sp.Protocol) == string(port.Protocol) {
			svcPort = &sp
			break
		}
	}
	if svcPort == nil {
		return nil, fmt.Errorf("service port not found, this should never happen")
	}

	var esList discoveryv1.EndpointSliceList
	if err := r.List(ctx, &esList, client.InNamespace(svc.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name}); err != nil {
		return nil, err
	}

	ips := make(map[netip.AddrPort]bool)

	for _, es := range esList.Items {
		if !((es.AddressType == discoveryv1.AddressTypeIPv6 && r.config.UseIPv6Endpoints) ||
			(es.AddressType == discoveryv1.AddressTypeIPv4 && !r.config.UseIPv6Endpoints)) {
			continue
		}

		var epPort *discoveryv1.EndpointPort
		for _, epp := range es.Ports {
			if (epp.Name != nil && svcPort.Name == *epp.Name) || (epp.Name == nil && svcPort.Name == "") {
				epPort = &epp
				break
			}
		}
		if epPort == nil {
			continue
		}

		// TODO: I'm not entirely sure what to do here?
		if epPort.Port == nil {
			// no idea if this is even possible ... we were unable to find targetPort - so we skip
			if svcPort.TargetPort.Type == intstr.String {
				continue
			}

			epPort.Port = &svcPort.TargetPort.IntVal
		}

		for _, ep := range es.Endpoints {
			ready := true
			if ep.Conditions.Ready != nil {
				ready = *ep.Conditions.Ready
			}

			if r.config.AddressSource == internal.AddressSourceNode {
				if ep.NodeName != nil && svcPort.NodePort != 0 {
					ip, err := r.getNodeAddress(ctx, *ep.NodeName)
					if err != nil {
						// skip
						continue
					}

					ips[netip.AddrPortFrom(*ip, uint16(svcPort.NodePort))] = ready
				}
			} else {
				for _, addr := range ep.Addresses {
					ip, err := netip.ParseAddr(addr)
					if err != nil {
						return nil, err
					}

					ips[netip.AddrPortFrom(ip, uint16(*epPort.Port))] = ready
				}
			}
		}
	}

	var ipList []netip.AddrPort
	for ip, ready := range ips {
		if ready {
			ipList = append(ipList, ip)
		}
	}

	sort.Slice(ipList, func(i, j int) bool {
		return ipList[i].Addr().Less(ipList[j].Addr())
	})

	var endpoints []graph.ServiceEndpoint

	for _, ip := range ipList {
		endpoints = append(endpoints, graph.ServiceEndpoint{
			AddrPort: ip,
			Protocol: port.Protocol,
		})
	}

	return endpoints, nil
}

func (r *ServiceReconciler) buildServiceData(ctx context.Context, svc *corev1.Service, ports []graph.ServicePort) (*graph.ServiceData, error) {
	var useProxyProtocol bool
	if svc.Annotations[proxyProtocolAnnotation] == "true" {
		useProxyProtocol = true
	}

	var idleTimeout *time.Duration
	if svc.Annotations[idleTimeoutAnnotation] != "" {
		dur, err := time.ParseDuration(svc.Annotations[idleTimeoutAnnotation])
		if err != nil {
			return nil, err
		}
		idleTimeout = &dur
	}

	var allowedIPRanges []netip.Prefix
	if len(svc.Spec.LoadBalancerSourceRanges) > 0 {
		for _, ip := range svc.Spec.LoadBalancerSourceRanges {
			prefix, err := netip.ParsePrefix(ip)
			if err != nil {
				return nil, err
			}

			allowedIPRanges = append(allowedIPRanges, prefix)
		}
	}

	data := graph.NewServiceData()

	for _, port := range ports {
		endpoints, err := r.buildEndpoints(ctx, svc, port)
		if err != nil {
			return nil, err
		}

		data.Ports[port] = graph.ServicePortData{
			Endpoints:        endpoints,
			UseProxyProtocol: useProxyProtocol,
			IdleTimeout:      idleTimeout,
			AllowedIPRanges:  allowedIPRanges,
		}
	}

	return data, nil
}

func (r *ServiceReconciler) findServiceForEndpoint(ctx context.Context, endpointSlice client.Object) []reconcile.Request {
	svcName := endpointSlice.GetLabels()[discoveryv1.LabelServiceName]
	if svcName == "" {
		return nil
	}

	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      svcName,
				Namespace: endpointSlice.GetNamespace(),
			},
		},
	}
}

func (r *ServiceReconciler) getNodeAddress(ctx context.Context, nodeName string) (*netip.Addr, error) {
	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: nodeName}, &node); err != nil {
		return nil, err
	}

	for _, addr := range node.Status.Addresses {
		if addr.Type != r.config.NodeAddressType {
			continue
		}

		ip, err := netip.ParseAddr(addr.Address)
		if err != nil {
			continue
		}

		if r.config.UseIPv6Endpoints && ip.Is6() {
			return &ip, nil
		} else if !r.config.UseIPv6Endpoints && ip.Is4() {
			return &ip, nil
		}
	}

	return nil, noValidNodeAddressError
}

func (r *ServiceReconciler) getServicePorts(svc *corev1.Service) []graph.ServicePort {
	var ports []graph.ServicePort

	for _, port := range svc.Spec.Ports {
		if port.Protocol == corev1.ProtocolTCP {
			ports = append(ports, graph.ServicePort{
				Port:     port.Port,
				Protocol: net.TCP,
			})
		} else if port.Protocol == corev1.ProtocolUDP {
			ports = append(ports, graph.ServicePort{
				Port:     port.Port,
				Protocol: net.UDP,
			})
		}
	}

	return ports
}

func (r *ServiceReconciler) shouldManage(svc *corev1.Service) bool {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return false
	}

	var svcClass string
	if svc.Spec.LoadBalancerClass != nil {
		svcClass = *svc.Spec.LoadBalancerClass
	}

	if svcClass != r.config.LoadBalancerClass {
		return false
	}

	return true
}

func (r *ServiceReconciler) updateStatus(ctx context.Context, svc *corev1.Service) error {
	var ing []corev1.LoadBalancerIngress
	for _, addr := range r.config.IngressStatus {
		if addr.IP != nil {
			ing = append(ing, corev1.LoadBalancerIngress{
				IP: addr.IP.String(),
			})
		} else {
			ing = append(ing, corev1.LoadBalancerIngress{
				Hostname: addr.Hostname,
			})
		}
	}

	svc.Status.LoadBalancer.Ingress = ing

	return r.Status().Update(ctx, svc)
}
