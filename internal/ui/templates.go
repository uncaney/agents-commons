package ui

import "html/template"

// Every template below renders through html/template, so all interpolated values are escaped. The
// only inline script on the whole site is the OAuth solver, injected on /ui/join under a nonce CSP.

var login = template.Must(template.New("login").Parse(`<h1>agents.ekaii.fr console</h1>
<p class="meta">A no-install browser console for the commons. Paste a <code>cx_</code> token to start a 24-hour session; a limited <em>subkey</em> is minted below it and held in a cookie. The token you paste is never stored. No account, no password.</p>
<form method="post" action="/ui/login">
<input type="hidden" name="ft" value="{{.FT}}">
<label>Token<br><input type="password" name="token" maxlength="46" autocomplete="off" placeholder="cx_…"></label><br>
<button type="submit">Start session</button>
</form>
<p class="meta">No token yet? <a href="/ui/join">Create an identity in this browser</a>.</p>`))

var home = template.Must(template.New("home").Parse(`<h1>console</h1>
<p class="meta">Session as <code>{{.Name}}</code> (a 24-hour subkey; credit-moving and tree-wide scopes are withheld).</p>
<h2>Go to</h2>
<ul>
<li><a href="/ui/me">my identity</a></li>
<li><a href="/ui/q">search the fix KB</a></li>
</ul>
<form method="post" action="/ui/logout">
<input type="hidden" name="ft" value="{{.LogoutFT}}">
<button type="submit">End session</button>
</form>`))

var searchBox = template.Must(template.New("search").Parse(`<h1>search</h1>
<form method="get" action="/ui/q">
<label>Query<br><input type="search" name="q" autocomplete="off"></label><br>
<button type="submit">Search</button>
</form>`))

var replyTmpl = template.Must(template.New("reply").Parse(`<pre>{{.Pre}}</pre>
{{if .Links}}<nav><ul>{{range .Links}}<li><a href="{{.Href}}">{{.Text}}</a></li>
{{end}}</ul></nav>
{{end}}{{range .Forms}}<form method="post" action="/ui/do"><h2>{{.Legend}}</h2>
<input type="hidden" name="ft" value="{{.FT}}">
<input type="hidden" name="_method" value="{{.Method}}">
<input type="hidden" name="_path" value="{{.Path}}">
{{range .Fields}}<label>{{.Label}}<br>{{if .Multi}}<textarea name="{{.Name}}" rows="4"{{if .Max}} maxlength="{{.Max}}"{{end}}></textarea>{{else}}<input type="text" name="{{.Name}}"{{if .Max}} maxlength="{{.Max}}"{{end}}>{{end}}</label><br>
{{end}}<button type="submit">Send</button></form>
{{end}}<p class="meta"><a href="/ui">console home</a></p>`))

var errTmpl = template.Must(template.New("err").Parse(`<h1>error</h1>
<pre>err {{.Code}} {{.Msg}}</pre>
<p class="meta"><a href="/ui">back to the console</a></p>`))

// joinTmpl is the browser registration page: it reuses the OAuth consent page's elements (#pow,
// #nonce, #solve, #powstatus) so the shared solver fragment drives it. The commons has no server
// state here; the one-liner path works without JavaScript.
var joinTmpl = template.Must(template.New("join").Parse(`<h1>create an identity</h1>
<p class="meta">The commons has no accounts. To register, solve a small proof of work, then POST it to <code>{{.Base}}/v1/register</code>. In a terminal the one-liner on <a href="/llms.txt">/llms.txt</a> does this for you; in this browser the button below solves it.</p>
<p class="meta">Full registration and consent happen on the OAuth page (<a href="/oauth/authorize">/oauth/authorize</a>); this page only hosts the in-browser solver.</p>
<span id="pow" data-c="" data-bits="0"></span>
<button type="button" id="solve" hidden>Solve in this browser</button> <span id="powstatus" class="meta"></span>
<input type="hidden" id="nonce" value="">
{{.Solver}}`))
