# phantomalias-site

Static site, no build step. Dark theme. Multi-post blog driven by a JSON
manifest and markdown files.

## Files

```
.
├── index.html              landing page
├── blog.html               post listing (reads posts.json)
├── post.html               single-post viewer (?p=<slug>)
├── style.css               shared theme
├── posts.json              post manifest (slug, title, date, summary)
├── posts/
│   └── phantom-alias.md    first post body (no title — comes from posts.json)
└── README.md               this file
```

## Enable GitHub Pages

If the site is at the repo root:

1. **Settings → Pages**
2. **Source**: *Deploy from a branch*
3. **Branch**: `main`, **Folder**: `/ (root)`
4. Save.

If the site is in `<username>.github.io`, it's served at the apex automatically.

## Add a new post

1. Write `posts/<slug>.md`. Don't include the title — the post page renders it
   from `posts.json`. Just write the body in markdown. Use fenced code blocks
   with a language hint (` ```cpp `, ` ```python `, etc.) for syntax highlighting.

2. Add an entry to `posts.json`:

   ```json
   {
     "posts": [
       {
         "slug": "your-slug",
         "title": "Your post title",
         "date": "2026-08-01",
         "summary": "One-sentence summary for the post list."
       },
       { "slug": "phantom-alias", ... }
     ]
   }
   ```

   Slug must match the filename without `.md`. Date is ISO `YYYY-MM-DD`. The
   list page sorts newest first by date.

3. Commit and push. Pages picks it up within a minute.

That's it. No build, no Jekyll, no front-matter, no manifest tooling. Just
markdown + JSON.

## URL conventions

- Landing: `/`
- Post list: `/blog.html`
- Single post: `/post.html?p=<slug>` (e.g. `/post.html?p=phantom-alias`)

These are stable — share `/post.html?p=...` links anywhere.

## Pre-publish edits

Find-and-replace `YOUR_GITHUB` across `index.html`, `blog.html`, `post.html`
with the path to your **code** repo (e.g. `your-username/phantomalias`).
Three files, ~6 occurrences total.

## How it works

- `blog.html` fetches `posts.json` and renders a list of `<a>` tags pointing
  at `post.html?p=<slug>`.
- `post.html` reads `?p=<slug>` from the URL, fetches `posts/<slug>.md`, and
  renders it with [marked.js](https://marked.js.org) and
  [Prism.js](https://prismjs.com) for syntax highlighting (both pulled from
  cdnjs). The post's title and date come from the matching `posts.json` entry.
- No state, no router, no build. Pages serves the static files; the browser
  does the rest.

## Theme

Single CSS file. CSS variables at the top of `style.css` control the palette
— swap `--accent` for a different accent color, swap `--bg` for a different
background.
