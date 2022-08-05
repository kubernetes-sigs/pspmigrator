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
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSuggestBaseline(t *testing.T) {

	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pod",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "nginx",
					Image: "nginx",
				},
			},
		},
	}

	level, err := SuggestedPodSecurityStandard(pod)
	if err != nil {
		t.Error(err.Error())
	}
	if level != "baseline" {
		t.Errorf("Expected baseline, but got %v\n", level)
	}

}

func newTrue() *bool {
	b := true
	return &b
}

func TestSuggestPrivileged(t *testing.T) {
	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pod",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            "nginx",
					Image:           "nginx",
					SecurityContext: &v1.SecurityContext{Privileged: newTrue()},
				},
			},
		},
	}

	level, err := SuggestedPodSecurityStandard(pod)
	if err != nil {
		t.Error(err.Error())
	}
	if level != "privileged" {
		t.Errorf("Expected privileged, but got %v\n", level)
	}
}
