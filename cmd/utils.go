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

package cmd

import (
	"context"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	psaApi "k8s.io/pod-security-admission/api"
)

func IgnoreNamespaceSelector(field string) string {
	ignoredNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}
	selectors := make([]fields.Selector, 0)
	for _, n := range ignoredNamespaces {
		selectors = append(selectors, fields.OneTermNotEqualSelector(field, n))
	}
	return fields.AndSelectors(selectors...).String()
}

func GetPods() (*v1.PodList, error) {
	listOptions := metav1.ListOptions{FieldSelector: IgnoreNamespaceSelector("metadata.namespace")}
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), listOptions)
	return pods, err
}

func GetPodsByNamespace(namespace string) (*v1.PodList, error) {
	listOptions := metav1.ListOptions{}
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), listOptions)
	return pods, err
}

func GetNamespaces() (*v1.NamespaceList, error) {
	listOptions := metav1.ListOptions{FieldSelector: IgnoreNamespaceSelector("metadata.name")}
	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), listOptions)
	return namespaces, err
}

func ApplyPSSLevel(namespace *v1.Namespace, level psaApi.Level, control string) error {
	namespace.Labels["pod-security.kubernetes.io/"+control] = string(level)
	_, err := clientset.CoreV1().Namespaces().Update(context.TODO(), namespace, metav1.UpdateOptions{})
	return err
}

func NamespaceHasPSALabels(namespace *v1.Namespace) bool {
	for k, _ := range namespace.Labels {
		if strings.HasPrefix(k, "pod-security.kubernetes.io") {
			return true
		}
	}
	return false
}
