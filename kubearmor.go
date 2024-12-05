package main

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func checkSensitiveDirs(config *rest.Config, sensitiveDirs []string, labelSelectors []string) ([]string, bool, error) {
	// Create in-cluster config
	var Assets []string
	var matched bool
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	// Define KubeArmorPolicy GVR
	gvr := schema.GroupVersionResource{
		Group:    "security.kubearmor.com",
		Version:  "v1",
		Resource: "kubearmorpolicies",
	}

	// List all policies across all namespaces
	policies, err := dynamicClient.Resource(gvr).Namespace("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("failed to list policies: %w", err)
	}

	// Convert labelSelectors []string to a map for easy matching
	labelSelectorMap := make(map[string]string)
	for _, selector := range labelSelectors {
		parts := strings.Split(selector, "=")
		if len(parts) == 2 {
			labelSelectorMap[parts[0]] = parts[1]
		}
	}

	for _, policy := range policies.Items {
		spec, ok := policy.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check if the policy matches the specified labels
		selector, ok := spec["selector"].(map[string]interface{})
		if ok {
			matchLabels, ok := selector["matchLabels"].(map[string]interface{})
			if ok {
				// Check if the labels match the provided label selectors (app=value)
				matches := true
				for key, value := range labelSelectorMap {
					if policyValue, exists := matchLabels[key]; !exists || policyValue != value {
						matches = false
						break
					}
				}

				// If the policy matches the label selector, continue checking for sensitive directories
				if matches {
					fmt.Printf("Policy %s matches label selector: %v\n", policy.GetName(), labelSelectorMap)
				} else {
					continue
				}
			}
		}

		file, ok := spec["file"].(map[string]interface{})
		if !ok {
			continue
		}

		matchDirs, ok := file["matchDirectories"].([]interface{})
		if !ok {
			continue
		}

		for _, dir := range matchDirs {
			dirMap, ok := dir.(map[string]interface{})
			if !ok {
				continue
			}

			dirPath, ok := dirMap["dir"].(string)
			if !ok {
				continue
			}

			action, ok := dirMap["action"].(string)
			if !ok {
				continue
			}

			for _, sensitiveDir := range sensitiveDirs {
				if dirPath == sensitiveDir {
					fmt.Printf("Found sensitive asset in policy %s:\n  Path: %s\n  Action: %s\n",
						policy.GetName(), dirPath, action)
					Assets = append(Assets, dirPath)
					matched = true
				}
			}
		}

		// Check matchPaths
		if matchPaths, ok := file["matchPaths"].([]interface{}); ok {
			for _, path := range matchPaths {
				pathMap, ok := path.(map[string]interface{})
				if !ok {
					continue
				}

				filePath, ok := pathMap["path"].(string)
				if !ok {
					continue
				}

				action, ok := pathMap["action"].(string)
				if !ok {
					continue
				}

				// readOnly, _ := pathMap["readOnly"].(bool)

				for _, sensitiveDir := range sensitiveDirs {
					if filePath == sensitiveDir {
						fmt.Printf("Found sensitive asset in policy %s:\n  Path: %s\n  Action: %s\n",
							policy.GetName(), filePath, action)
						Assets = append(Assets, filePath)
						matched = true

					}
				}
			}
		}

	}
	return labelSelectors, matched, nil
}
