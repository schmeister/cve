# cve

## flags

Usage of /tmp/go-build3222154040/b001/exe/main:  
- analysisDetails string  
    - Details  
- analysisJustification string  
    - [REQUIRES_ENVIRONMENT REQUIRES_CONFIGURATION NOT_SET REQUIRES_DEPENDENCY CODE_NOT_PRESENT PROTECTED_BY_MITIGATING_CONTROL CODE_NOT_REACHABLE PROTECTED_AT_PERIMETER PROTECTED_BY_COMPILER PROTECTED_AT_RUNTIME]  
         (default "NOT_SET")  
- analysisState string  
    - [NOT_AFFECTED FALSE_POSITIVE NOT_SET RESOLVED IN_TRIAGE EXPLOITABLE]  
         (default "NOT_SET")  
- apikey string  
    - X-Api-Key (default "odt_CnCius8VuTy6f7kxqEco7HAoIApQGxd2")  
- comment string  
    - Comment to add to vulnerability
- key string  
    - Label to be searched (such as "firefox") 
- listC  
    - List components for project  
- listP  
    - List projects  
- listV  
    - List vulnerabilities for project  
- project string  
    - (default "daa3585b-1013-4dcf-b8c6-9d32b00077ec")  
- simulate  
    - Simulate update only - If **true** only displays what will be updated  
- suppressed  
    - Suppress the CVE - essentially hide it  
- uri string  
    - URI (default "http://10.125.140.97:8081")  
- us  
    - Update Supressed vulnerability - If false only non-suppressed vulnerabilities be updated

## Sample Calls

### Sample #1

```
go run cmd/main.go -IS=true -CP="util-linux"
```

Include Suppressed Vulnerabilities.
Update components of "util-linux"

Default values:  

* State: **NOT_SET**
* Justification: **NOT_SET**
* Vendor Response: **CAN_NOT_FIX**
* Default Comments
* Default Details


### Sample #2

Set *key* to **firefox** to only update Firefox components.  
Set *State, Justification*, and *Details*.  
Set *Suppressed* to **true** hides vulnerability  
Set *simulate* to **false** - will update vulnerabilities  
Set *us* (update suppressed) to **false** - if vulnerability is suppressed, do not update again.

```
go run cmd/main.go -key="firefox" \
-analysisState="NOT_AFFECTED" \
-analysisJustification="PROTECTED_AT_PERIMETER" \
-analysisDetails="Not reachable by users - ACP running in Kiosk mode" \
-suppressed=true \
-simulate=false \
-us=false
```

This sample works on Vulernabilities in the default **project**:  
<span style="color:red">daa3585b-1013-4dcf-b8c6-9d32b00077ec </span>(<span style="color:orange">**GSS - ACP OS**</span>)  
**-project="Project Object Identifier UUID"** to use a different project
