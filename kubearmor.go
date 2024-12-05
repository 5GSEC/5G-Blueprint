package main

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func checkSensitiveDirs(config *rest.Config, sensitiveDirs []string) ([]string, bool, error) {
	// Create in-cluster config
	var Assets []string
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

	for _, policy := range policies.Items {
		spec, ok := policy.Object["spec"].(map[string]interface{})
		if !ok {
			continue
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
					// return dirPath, nil
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

					}
				}
			}
		}

	}
	return Assets, true, nil
}
