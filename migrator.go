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
	"log"

	v1 "k8s.io/api/core/v1"

	psaapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

var evaluator policy.Evaluator

func init() {
	var err error
	evaluator, err = policy.NewEvaluator(policy.DefaultChecks())
	if err != nil {
		log.Println("Error initializing evaluator:", err.Error())
	}
}

func SuggestedPodSecurityStandard(pod *v1.Pod) (psaapi.Level, error) {
	for _, apiLevel := range []psaapi.Level{psaapi.LevelRestricted, psaapi.LevelBaseline} {
		result := policy.AggregateCheckResults(evaluator.EvaluatePod(
			psaapi.LevelVersion{Level: apiLevel, Version: psaapi.LatestVersion()}, &pod.ObjectMeta, &pod.Spec))

		if result.Allowed {
			return apiLevel, nil
		}
	}
	return psaapi.LevelPrivileged, nil
}
