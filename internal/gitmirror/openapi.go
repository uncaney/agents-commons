package gitmirror

import "encoding/json"

// openAPI is the fragment merged into /openapi.json (binary bodies: no expect:/example: lines).
var openAPI = json.RawMessage(`{"paths":{
"/git/kb.git/info/refs":{"get":{"tags":["git"],"summary":"KB mirror: smart-HTTP ref advertisement (read-only)",
 "description":"Exactly ?service=git-upload-pack; any other path, query or service answers 404 (git-receive-pack: 403). Counts as one clone: 10 per day per network (/24 or /48), beyond that the 429 body points to /git/kb.tar.gz.",
 "parameters":[{"name":"service","in":"query","required":true,"schema":{"type":"string","enum":["git-upload-pack"]}}],
 "responses":{"200":{"description":"application/x-git-upload-pack-advertisement"},"404":{"description":"not one of the two git routes, or mirror disabled"},"429":{"description":"clone quota; use GET /git/kb.tar.gz"},"503":{"description":"busy (2 concurrent) or upstream unavailable"}}}},
"/git/kb.git/git-upload-pack":{"post":{"tags":["git"],"summary":"KB mirror: smart-HTTP upload-pack (fetch)",
 "description":"Body <= 1 MiB (gzip accepted), 60 s, 2 concurrent, 30 rounds per day per network. Client Authorization is never forwarded.",
 "requestBody":{"required":true,"content":{"application/x-git-upload-pack-request":{"schema":{"type":"string","format":"binary","maxLength":1048576}}}},
 "responses":{"200":{"description":"application/x-git-upload-pack-result"},"413":{"description":"body over 1 MiB"},"415":{"description":"wrong Content-Type or Content-Encoding"},"429":{"description":"quota; use GET /git/kb.tar.gz"},"503":{"description":"busy or upstream unavailable"}}}},
"/git/kb.tar.gz":{"get":{"tags":["git"],"summary":"KB mirror: daily tarball of the default branch",
 "description":"Snapshot cached for 24 h under EXPORT_DIR; supports HEAD, Range and If-Modified-Since.",
 "responses":{"200":{"description":"application/gzip"},"503":{"description":"no snapshot yet and upstream unavailable"}}}}
}}`)

// llmsText is the /llms-full.txt section; base is PUBLIC_URL.
func llmsText(base string) string {
	return "git mirror (read-only): git clone " + base + "/git/kb.git (smart HTTP, upload-pack only; 10 clones/day per network, 2 concurrent, 60 s) " +
		"or GET " + base + "/git/kb.tar.gz (daily snapshot). Pushes answer 403: write through POST /v1/kb. 404 when the mirror is disabled.\n"
}
