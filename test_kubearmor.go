package main

import (
	"context"
	"fmt"
	"os"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// Load in-cluster Kubernetes config
	edgeconfig, err := clientcmd.BuildConfigFromFlags("", "/home/ubuntu/.kube/edge-kubeconfig")
	if err != nil {
		panic(err.Error())
	}
	// Initialize Kubernetes dynamic client
	dynClient, err := dynamic.NewForConfig(edgeconfig)
	if err != nil {
		fmt.Printf("Error creating dynamic client: %v\n", err)
		os.Exit(1)
	}

	// Define the KubeArmorPolicy GVR
	kubeArmorPolicyGVR := schema.GroupVersionResource{
		Group:    "security.kubearmor.com",
		Version:  "v1",
		Resource: "kubearmorpolicies",
	}

	// Fetch all KubeArmor policies in the namespace
	namespace := "oai-ran-du"
	policies, err := dynClient.Resource(kubeArmorPolicyGVR).Namespace(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Error fetching KubeArmor policies: %v\n", err)
		os.Exit(1)
	}

	// Workload and sensitive assets
	workloadLabels := map[string]string{"App": "oai-gnb-du"}
	sensitiveAssets := []string{
		"/run/secrets/kubernetes.io/serviceaccount/",
		"/opt/oai-gnb/etc/",
	}

	// Define CEL environment
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("policy", decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar("workloadLabels", decls.NewMapType(decls.String, decls.String)),
			decls.NewVar("sensitiveAssets", decls.NewListType(decls.String)),
		),
	)
	if err != nil {
		fmt.Printf("Error creating CEL environment: %v\n", err)
		os.Exit(1)
	}

	// Define CEL Expression
	expression := `
		policy.spec.selector.matchLabels.matches(workloadLabels) &&
		sensitiveAssets.exists(sensitiveAsset, 
			policy.spec.file.matchPaths.exists(path, path.startsWith(sensitiveAsset)) || 
			policy.spec.file.matchDirectories.exists(dir, sensitiveAsset.startsWith(dir.dir))
		)
	`

	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		fmt.Printf("Error compiling CEL expression: %v\n", issues.Err())
		os.Exit(1)
	}

	for _, policy := range policies.Items {
		eval, _ := env.Program(ast)
		inputs := map[string]interface{}{
			"policy":          policy.Object,
			"workloadLabels":  workloadLabels,
			"sensitiveAssets": sensitiveAssets,
		}

		out, _, err := eval.Eval(inputs)
		if err != nil {
			fmt.Printf("Error evaluating CEL: %v\n", err)
			continue
		}

		if out.Equal(types.True).(ref.Val).Value().(bool) {
			fmt.Println("Policy protects sensitive assets:", policy.GetName())
		} else {
			fmt.Println("Policy does NOT protect sensitive assets:", policy.GetName())
		}
	}
}
