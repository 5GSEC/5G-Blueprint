package main

import (
	"html/template"
	"net/http"
)

type Checkpoint struct {
	Name        string
	Description string
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Sample data for RiskList
		riskData := RiskView{
			RiskID:          "R001",
			RiskDescription: "A critical vulnerability in Kubernetes",
			Checkpoints: []Checkpoint{
				{Name: "Checkpoint 1", Description: "Initial analysis"},
				{Name: "Checkpoint 2", Description: "Testing patch"},
			},
			Assets:          []string{"Asset1", "Asset2"},
			Exploitability:  "High",
			Severity:        "Critical",
			RemediationTime: "1 Week",
			Solutions:       "Apply security patch",
			References:      []string{"https://link1.com", "https://link2.com"},
		}

		tmpl, err := template.New("accordion").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk List Accordion</title>
    <style>
        .accordion { background-color: #f1f1f1; padding: 10px; cursor: pointer; width: 100%; text-align: left; border: none; outline: none; font-size: 15px; }
        .panel { padding: 0 18px; display: none; overflow: hidden; background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h2>Risk List Accordion</h2>

    <button class="accordion">{{.RiskID}} - {{.RiskDescription}}</button>
    <div class="panel">
        <p><strong>Exploitability:</strong> {{.Exploitability}}</p>
        <p><strong>Severity:</strong> {{.Severity}}</p>
        <p><strong>Remediation Time:</strong> {{.RemediationTime}}</p>
        <p><strong>Solutions:</strong> {{.Solutions}}</p>
        
        <h4>Checkpoints:</h4>
        <ul>
            {{range .Checkpoints}}
            <li>{{.Name}}: {{.Description}}</li>
            {{end}}
        </ul>

        <h4>Assets:</h4>
        <ul>
            {{range .Assets}}
            <li>{{.}}</li>
            {{end}}
        </ul>

        <h4>References:</h4>
        <ul>
            {{range .References}}
            <li><a href="{{.}}" target="_blank">{{.}}</a></li>
            {{end}}
        </ul>
    </div>

    <script>
        var acc = document.getElementsByClassName("accordion");
        for (var i = 0; i < acc.length; i++) {
            acc[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var panel = this.nextElementSibling;
                if (panel.style.display === "block") {
                    panel.style.display = "none";
                } else {
                    panel.style.display = "block";
                }
            });
        }
    </script>
</body>
</html>
`)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Render template with risk data
		tmpl.Execute(w, riskData)
	})

	http.ListenAndServe(":8080", nil)
}
