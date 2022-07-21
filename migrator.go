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
	v1 "k8s.io/api/core/v1"

	"k8s.io/pod-security-admission/api"
	psaapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

func SuggestedPodSecurityStandard(pod *v1.Pod) (psaapi.Level, error) {
	evaluator, err := policy.NewEvaluator(policy.DefaultChecks())
	if err != nil {
		return "", err
	}
	apiVersion, err := api.ParseVersion("latest")
	if err != nil {
		return "", err
	}
	for _, level := range []string{"restricted", "baseline"} {
		apiLevel, err := psaapi.ParseLevel(level)
		if err != nil {
			return "", err
		}
		result := policy.AggregateCheckResults(evaluator.EvaluatePod(
			psaapi.LevelVersion{Level: apiLevel, Version: apiVersion}, &pod.ObjectMeta, &pod.Spec))

		if result.Allowed {
			return apiLevel, nil
		}
	}
	return api.LevelPrivileged, nil
}
