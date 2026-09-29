def analyze(http_result):
    technologies = []

    headers = {
        key.lower(): value
        for key, value in http_result.get(
            "headers",
            {}
        ).items()
    }

    content = http_result.get(
        "content",
        ""
    )

    server = headers.get(
        "server",
        ""
    )

    powered_by = headers.get(
        "x-powered-by",
        ""
    )

    server_lower = server.lower()
    powered_lower = powered_by.lower()
    content_lower = content.lower()

    # Web Server / Proxy detection
    if "cloudflare" in server_lower:
        technologies.append({
            "name": "Cloudflare",
            "category": "CDN / Proxy",
            "confidence": "high",
            "evidence": f"Server: {server}",
        })

    elif "nginx" in server_lower:
        technologies.append({
            "name": "Nginx",
            "category": "Web Server",
            "confidence": "high",
            "evidence": f"Server: {server}",
        })

    elif "apache" in server_lower:
        technologies.append({
            "name": "Apache",
            "category": "Web Server",
            "confidence": "high",
            "evidence": f"Server: {server}",
        })

    elif "microsoft-iis" in server_lower:
        technologies.append({
            "name": "Microsoft IIS",
            "category": "Web Server",
            "confidence": "high",
            "evidence": f"Server: {server}",
        })

    # Powered By detection
    if "php" in powered_lower:
        technologies.append({
            "name": "PHP",
            "category": "Runtime",
            "confidence": "high",
            "evidence": f"X-Powered-By: {powered_by}",
        })

    elif "express" in powered_lower:
        technologies.append({
            "name": "Express",
            "category": "Framework",
            "confidence": "high",
            "evidence": f"X-Powered-By: {powered_by}",
        })

    elif "asp.net" in powered_lower:
        technologies.append({
            "name": "ASP.NET",
            "category": "Framework",
            "confidence": "high",
            "evidence": f"X-Powered-By: {powered_by}",
        })

    # HTML technology detection

    if "wp-content/" in content_lower:
        technologies.append({
            "name": "WordPress",
            "category": "CMS",
            "confidence": "high",
            "evidence": "HTML contains wp-content/",
        })

    elif "wp-includes/" in content_lower:
        technologies.append({
            "name": "WordPress",
            "category": "CMS",
            "confidence": "high",
            "evidence": "HTML contains wp-includes/",
        })

    if "joomla" in content_lower:
        technologies.append({
            "name": "Joomla",
            "category": "CMS",
            "confidence": "medium",
            "evidence": "HTML contains Joomla fingerprint",
        })

    if "drupal-settings-json" in content_lower:
        technologies.append({
            "name": "Drupal",
            "category": "CMS",
            "confidence": "high",
            "evidence": "HTML contains drupal-settings-json",
        })

    if "__next_data__" in content_lower:
        technologies.append({
            "name": "Next.js",
            "category": "Framework",
            "confidence": "high",
            "evidence": "HTML contains __NEXT_DATA__",
        })

    if "react" in content_lower:
        technologies.append({
            "name": "React",
            "category": "JavaScript Framework",
            "confidence": "medium",
            "evidence": "HTML contains React fingerprint",
        })

    if "vue" in content_lower:
        technologies.append({
            "name": "Vue.js",
            "category": "JavaScript Framework",
            "confidence": "medium",
            "evidence": "HTML contains Vue fingerprint",
        })

    if "angular" in content_lower:
        technologies.append({
            "name": "Angular",
            "category": "JavaScript Framework",
            "confidence": "medium",
            "evidence": "HTML contains Angular fingerprint",
        })

    if "jquery" in content_lower:
        technologies.append({
            "name": "jQuery",
            "category": "JavaScript Library",
            "confidence": "medium",
            "evidence": "HTML contains jQuery fingerprint",
        })

    if "bootstrap" in content_lower:
        technologies.append({
            "name": "Bootstrap",
            "category": "CSS Framework",
            "confidence": "medium",
            "evidence": "HTML contains Bootstrap fingerprint",
        })

    if "tailwind" in content_lower:
        technologies.append({
            "name": "Tailwind CSS",
            "category": "CSS Framework",
            "confidence": "medium",
            "evidence": "HTML contains Tailwind fingerprint",
        })

    if "laravel" in content_lower:
        technologies.append({
            "name": "Laravel",
            "category": "Framework",
            "confidence": "medium",
            "evidence": "HTML contains Laravel fingerprint",
        })

    if "django" in content_lower:
        technologies.append({
            "name": "Django",
            "category": "Framework",
            "confidence": "medium",
            "evidence": "HTML contains Django fingerprint",
        })

    return {
        "technologies": technologies,
        "findings": [],
    }
