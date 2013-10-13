package policy

import (
	"fmt"
)

func ExampleNewPolicy() {
	p := NewPolicy()
	p.SetId("policy-id")
	stmt := p.AddStatement()
	stmt.SetSid("statement-id")
	stmt.Effect = Allow
	stmt.AddPrincipal("*")
	stmt.AddAction("Describe*")
	stmt.Resource = "*"
	stmt.AddCondition(ConditionArnEquals, VarSourceIp, "10.0.0.0/8")

	fmt.Println(p)
	// Output:
	// {
	//     "Version": "2012-10-17",
	//     "Id": "policy-id",
	//     "Statement": [
	//         {
	//             "Sid": "statement-id",
	//             "Effect": "Allow",
	//             "Principal": {
	//                 "AWS": "*"
	//             },
	//             "Action": [
	//                 "Describe*"
	//             ],
	//             "Resource": "*",
	//             "Condition": {
	//                 "ArnEquals": {
	//                     "aws:SourceIp": [
	//                         "10.0.0.0/8"
	//                     ]
	//                 }
	//             }
	//         }
	//     ]
	// }
}
