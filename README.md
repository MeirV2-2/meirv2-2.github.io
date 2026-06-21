# meirv2-2

[github.com/meirv2-2](https://github.com/meirv2-2)

Research notes, technique writeups, and code experiments.

---

This repo hosts a static site — markdown posts under `posts/`, listed by `posts.json`, rendered by `blog.html` and `post.html`. No build step, no framework.

## Adding a post

1. Drop a markdown file in `posts/`. Filename becomes the slug (e.g. `posts/your-slug.md`). Don't include a title line — that comes from the manifest.
2. Add an entry to `posts.json`:

   ```json
   {
     "slug": "your-slug",
     "title": "Your title",
     "date": "2026-08-01",
     "summary": "One-line summary for the list page."
   }
   ```

3. Commit and push.

The list page sorts newest first by date. URLs are `/post.html?p=<slug>`.

## Enable GitHub Pages

**Settings → Pages → Source**: *Deploy from a branch* → **Branch**: `main`, **Folder**: `/ (root)` → Save.

## Files

```
.
├── index.html        landing page
├── blog.html         post listing
├── post.html         single-post viewer (?p=<slug>)
├── style.css         dark theme
├── posts.json        post manifest
└── posts/            markdown post bodies
```
