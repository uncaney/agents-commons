package feed

import (
	"encoding/xml"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Atom 1.0 (RFC 4287) through encoding/xml: every text node is escaped by the encoder.
type atomFeed struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	Title   string      `xml:"title"`
	ID      string      `xml:"id"`
	Updated string      `xml:"updated"`
	Links   []atomLink  `xml:"link"`
	Author  atomAuthor  `xml:"author"`
	Entries []atomEntry `xml:"entry"`
}

type atomLink struct {
	Rel  string `xml:"rel,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
	Href string `xml:"href,attr"`
}

type atomAuthor struct {
	Name string `xml:"name"`
	URI  string `xml:"uri,omitempty"`
}

type atomText struct {
	Type string `xml:"type,attr"`
	Text string `xml:",chardata"`
}

type atomCategory struct {
	Term string `xml:"term,attr"`
}

type atomEntry struct {
	ID         string         `xml:"id"`
	Title      string         `xml:"title"`
	Links      []atomLink     `xml:"link"`
	Updated    string         `xml:"updated"`
	Published  string         `xml:"published"`
	Author     *atomAuthor    `xml:"author,omitempty"`
	Summary    atomText       `xml:"summary"`
	Categories []atomCategory `xml:"category"`
}

func atomTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func renderAtom(m *meta) []byte {
	f := atomFeed{
		Title:   m.title,
		ID:      "tag:" + host() + "," + tagYear + ":f/" + m.name,
		Updated: atomTime(m.feedUpdated()),
		Links: []atomLink{
			{Rel: "self", Type: linkTypes[Atom], Href: m.self},
			{Rel: "alternate", Type: "text/html", Href: m.home},
			{Rel: "alternate", Type: linkTypes[JSON], Href: m.alt},
		},
		Author:  atomAuthor{Name: host(), URI: m.home},
		Entries: make([]atomEntry, 0, len(m.items)),
	}
	for _, it := range m.items {
		f.Entries = append(f.Entries, atomEntryOf(m.idBase, it))
	}
	b, err := xml.Marshal(f)
	if err != nil { // only invalid UTF-8 can fail here, and SafeLine already removed it
		b = []byte("<feed xmlns=\"http://www.w3.org/2005/Atom\"><title>" + host() + "</title><id>" + f.ID + "</id><updated>" + f.Updated + "</updated></feed>")
	}
	return append([]byte(xml.Header), append(b, '\n')...)
}

func atomEntryOf(base string, it core.FeedItem) atomEntry {
	e := atomEntry{
		ID:        tagURI(base, it.ID),
		Title:     it.Title,
		Links:     []atomLink{{Rel: "alternate", Type: "text/html", Href: it.URL}},
		Updated:   atomTime(it.Updated),
		Published: atomTime(it.Published),
		Summary:   atomText{Type: "text", Text: it.Summary},
	}
	if it.Author != "" {
		e.Author = &atomAuthor{Name: it.Author, URI: authorURL(it.Author)}
	}
	for _, t := range it.Tags {
		e.Categories = append(e.Categories, atomCategory{Term: t})
	}
	return e
}
