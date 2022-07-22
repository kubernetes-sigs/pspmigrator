/*
Copyright 2022 The Kubernetes Authors.

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

package pspmigrator

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-test/deep"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	psaadmission "k8s.io/pod-security-admission/admission"
)

func GetContainerSecurityContexts(podSpec *v1.PodSpec) []*v1.SecurityContext {
	// TODO reuse VisitContainers from k8s pkg/api/pod/util.go
	scs := make([]*v1.SecurityContext, 0)
	for _, c := range podSpec.Containers {
		scs = append(scs, c.SecurityContext)
	}
	for _, c := range podSpec.InitContainers {
		scs = append(scs, c.SecurityContext)
	}
	for _, c := range podSpec.EphemeralContainers {
		scs = append(scs, c.SecurityContext)
	}
	return scs
}

func GetPSPAnnotations(annotations map[string]string) map[string]string {
	pspAnnotations := make(map[string]string)
	for ann, val := range annotations {
		if strings.Contains(ann, "seccomp.security") || strings.Contains(ann, "apparmor.security") {
			pspAnnotations[ann] = val
		}
	}
	return pspAnnotations
}

func FetchControllerPod(kind, name, namespace string, clientset *kubernetes.Clientset) (*metav1.ObjectMeta, *v1.PodSpec, error) {
	obj, err := FetchControllerObj(kind, name, namespace, clientset)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch controller: %w", err)
	}
	return psaadmission.DefaultPodSpecExtractor{}.ExtractPodSpec(obj)
}

func FetchControllerObj(kind, name, namespace string, clientset *kubernetes.Clientset) (runtime.Object, error) {
	// TODO review and document which controllers don't require special handling
	// https://github.com/kubernetes/pod-security-admission/blob/master/admission/admission.go#L93
	// for example, Deployments would fall under the ReplicaSet case so no need to have a case
	// statement for Deployments.
	switch kind {
	case "ReplicaSet":
		return clientset.AppsV1().ReplicaSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	case "DaemonSet":
		return clientset.AppsV1().DaemonSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	default:
		return nil, fmt.Errorf("unsupported controller kind %s", kind)
	}
}

// IsPodBeingMutatedByPSP returns whether a pod is likely mutated by a PSP object. It also returns the difference
// of the securityContext attribute between the parent controller (e.g. Deployment) and the running pod.
func IsPodBeingMutatedByPSP(pod *v1.Pod, clientset *kubernetes.Clientset) (mutating bool, diff []string, err error) {
	diff = make([]string, 0)
	if len(pod.ObjectMeta.OwnerReferences) > 0 {
		var owner metav1.OwnerReference
		for _, reference := range pod.ObjectMeta.OwnerReferences {
			if reference.Controller != nil && *reference.Controller == true {
				owner = reference
				break
			}
		}
		if owner.Kind == "Node" {
			// static pods launched by the node that can't be mutated
			return false, diff, nil
		}
		parentPodMeta, parentPodSpec, err := FetchControllerPod(owner.Kind, owner.Name, pod.Namespace, clientset)
		if err != nil {
			return false, diff, err
		}
		// TODO investigate if 1st party library can be used such as github.com/google/go-cmp or smth from k8s
		if diffNew := deep.Equal(GetContainerSecurityContexts(parentPodSpec), GetContainerSecurityContexts(&pod.Spec)); diffNew != nil {
			diff = append(diff, diffNew...)
		}
		if diffNew := deep.Equal(parentPodSpec.SecurityContext, pod.Spec.SecurityContext); diffNew != nil {
			diff = append(diff, diffNew...)
		}
		if diffNew := deep.Equal(GetPSPAnnotations(parentPodMeta.Annotations), GetPSPAnnotations(pod.ObjectMeta.Annotations)); diffNew != nil {
			diff = append(diff, diffNew...)
		}
	}
	if len(diff) > 0 {
		return true, diff, nil
	}
	return false, diff, nil
}

// IsPSPMutating checks wheter a PodSecurityPolicy is potentially mutating
// pods. It returns true if one of the fields or annotations used in the
// PodSecurityPolicy is suspected to be mutating pods. The field or annotations
// that are suspected to be mutating are returned as well.
func IsPSPMutating(pspObj *v1beta1.PodSecurityPolicy) (mutating bool, fields, annotations []string) {
	fields = make([]string, 0)
	annotations = make([]string, 0)

	if len(pspObj.Spec.DefaultAddCapabilities) > 0 {
		fields = append(fields, "DefaultAddCapabilities")
	}
	if len(pspObj.Spec.RequiredDropCapabilities) > 0 {
		fields = append(fields, "RequiredDropCapabilities")
	}
	if pspObj.Spec.SELinux.Rule != v1beta1.SELinuxStrategyRunAsAny {
		fields = append(fields, "SELinux")
	}
	if pspObj.Spec.RunAsUser.Rule != v1beta1.RunAsUserStrategyRunAsAny {
		fields = append(fields, "RunAsUser")
	}
	if pspObj.Spec.RunAsGroup != nil && pspObj.Spec.RunAsGroup.Rule == v1beta1.RunAsGroupStrategyMustRunAs {
		fields = append(fields, "RunAsGroup")
	}
	if pspObj.Spec.SupplementalGroups.Rule != v1beta1.SupplementalGroupsStrategyRunAsAny {
		fields = append(fields, "SupplementalGroups")
	}
	if pspObj.Spec.FSGroup.Rule != v1beta1.FSGroupStrategyRunAsAny {
		fields = append(fields, "FSGroup")
	}
	if pspObj.Spec.ReadOnlyRootFilesystem != false {
		fields = append(fields, "ReadOnlyRootFilesystem")
	}
	if pspObj.Spec.DefaultAllowPrivilegeEscalation != nil {
		fields = append(fields, "DefaultAllowPrivilegeEscalation")
	}
	if pspObj.Spec.AllowPrivilegeEscalation != nil && *pspObj.Spec.AllowPrivilegeEscalation != true {
		fields = append(fields, "AllowPrivilegeEscalation")
	}

	mutatingAnnotations := make(map[string]bool)
	mutatingAnnotations["seccomp.security.alpha.kubernetes.io/defaultProfileName"] = true
	mutatingAnnotations["apparmor.security.beta.kubernetes.io/defaultProfileName"] = true

	for k, _ := range pspObj.Annotations {
		if _, ok := mutatingAnnotations[k]; ok {
			annotations = append(annotations, k)
		}
	}

	if len(fields) > 0 || len(annotations) > 0 {
		return true, fields, annotations
	}

	return false, fields, annotations
}
