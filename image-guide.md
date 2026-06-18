# MIMOS Academy — Image Asset Setup Guide

This guide explains how to replace the template placeholders across your website pages with real image files.

All image files should be saved inside the **`assets/images/`** directory.

---

## Guide Table: Placeholder to Image Mapping

| Page | Section | Description in Placeholder | Recommended Filename | Ideal Ratio / Size |
| :--- | :--- | :--- | :--- | :--- |
| **Global** | Navbar / Auth pages | Logo Image | `assets/images/logo.png` | Horizontal or Square (Auto-scaled to 52px height) |
| **Home** (`index.html`) | Hero Section | Tech/Data Center Background | `assets/images/home_hero_bg.jpg` | 16:9 ratio (~1920x1080) |
| **Home** (`index.html`) | Knowledge Hub | Summit Event Image | `assets/images/summit_event_1.jpg` | 4:3 ratio (~800x600) |
| **Home** (`index.html`) | Knowledge Hub | Workshop Event Image | `assets/images/summit_event_2.jpg` | 4:3 ratio (~800x600) |
| **Home** (`index.html`) | Knowledge Hub | Experience Tour Image | `assets/images/summit_event_3.jpg` | 4:3 ratio (~800x600) |
| **Home** (`index.html`) | Infrastructure | Cloud Sandbox Lab | `assets/images/facility_sandbox.jpg` | 16:10 ratio (~800x500) |
| **Home** (`index.html`) | Infrastructure | Collaborative Workstation | `assets/images/facility_lab.jpg` | 16:10 ratio (~800x500) |
| **About** (`about.html`) | Hero Section | Team Working Background | `assets/images/about_hero_bg.jpg` | 16:9 ratio (~1920x1080) |
| **About** (`about.html`) | Intro Section | Team Photo (Students & Trainers) | `assets/images/about_team.jpg` | 4:3 ratio (~800x600) |
| **Programs** (`programs.html`) | Hero Header | Semiconductor / Chip Close-Up | `assets/images/programs_chip.jpg` | 4:3 ratio (~800x600) |
| **Programs** (`programs.html`) | Course Listing | VLSI Circuit Board | `assets/images/course_vlsi.jpg` | 16:10 ratio (~600x400) |
| **Programs** (`programs.html`) | Course Listing | Microchip Close-Up | `assets/images/course_microchip.jpg` | 16:10 ratio (~600x400) |
| **Programs** (`programs.html`) | Course Listing | Green PCB Board | `assets/images/course_pcb.jpg` | 16:10 ratio (~600x400) |
| **Program Detail** (`program-detail.html`) | Hero Header | Circuit Board / Engineering Bg | `assets/images/program_detail_hero.jpg` | 16:9 ratio (~1920x1080) |
| **Program Detail** (`program-detail.html`) | Registration | Scan to Enroll QR Code | `assets/images/qr_enroll.png` | 1:1 ratio (200x200) |
| **Program Detail** (`program-detail.html`) | Documentation | Programme Brochure Preview | `assets/images/brochure_preview.jpg` | A4 Portrait Ratio (~800x1130) |
| **Contact** (`contact.html`) | Header Section | Campus Aerial View | `assets/images/contact_campus.jpg` | 4:3 ratio (~800x600) |

---

## How to Apply the Images in Code

### Method A: Replacing HTML Picture Placeholders
Look for HTML code that contains the `placeholder-img` class. For example:
```html
<!-- BEFORE (Placeholder) -->
<div class="placeholder-img" style="width:100%;height:100%;">
  <span>VLSI Circuit Board</span>
</div>
```
Replace it with a standard HTML `<img>` tag matching the recommended filename:
```html
<!-- AFTER (With Real Image) -->
<img src="assets/images/course_vlsi.jpg" alt="VLSI Circuit Board" style="width:100%; height:100%; object-fit:cover;">
```

### Method B: Replacing CSS Background Placeholders (Heroes)
For page hero sections, look for the `.hero__bg` element:
```html
<!-- BEFORE (Placeholder) -->
<div class="hero__bg">
  <div class="placeholder-img placeholder-img--dark" style="width:100%;height:100%;">
    <span>Hero Background</span>
  </div>
</div>
```
Replace it with a background image tag:
```html
<!-- AFTER (With Real Image) -->
<div class="hero__bg">
  <img src="assets/images/home_hero_bg.jpg" alt="Hero Background">
</div>
```
*(The existing styles will automatically format the background image correctly as full-bleed with proper contrast overlays).*
