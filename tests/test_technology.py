from styxscan.technology import analyze


def test_server_detection():
    result = analyze({
        "headers": {
            "Server": "nginx"
        },
        "content": "",
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "Nginx"
        for tech in technologies
    )


def test_powered_by_detection():
    result = analyze({
        "headers": {
            "X-Powered-By": "PHP/8.3"
        },
        "content": "",
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "PHP"
        for tech in technologies
    )


def test_wordpress_html_detection():
    result = analyze({
        "headers": {},
        "content": """
            <html>
                <head>
                    <link
                        rel="stylesheet"
                        href="/wp-content/themes/test/style.css"
                    >
                </head>
            </html>
        """,
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "WordPress"
        for tech in technologies
    )


def test_nextjs_html_detection():
    result = analyze({
        "headers": {},
        "content": """
            <html>
                <script
                    id="__NEXT_DATA__"
                    type="application/json"
                >
                </script>
            </html>
        """,
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "Next.js"
        for tech in technologies
    )


def test_jquery_html_detection():
    result = analyze({
        "headers": {},
        "content": """
            <script src="/js/jquery-3.7.1.min.js">
            </script>
        """,
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "jQuery"
        for tech in technologies
    )


def test_bootstrap_html_detection():
    result = analyze({
        "headers": {},
        "content": """
            <link
                rel="stylesheet"
                href="/css/bootstrap.min.css"
            >
        """,
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "Bootstrap"
        for tech in technologies
    )


def test_tailwind_html_detection():
    result = analyze({
        "headers": {},
        "content": """
            <html class="tailwind">
                <body>
                    <div class="flex items-center">
                    </div>
                </body>
            </html>
        """,
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "Tailwind CSS"
        for tech in technologies
    )


def test_react_html_detection():
    result = analyze({
        "headers": {},
        "content": """
            <html>
                <div id="root"></div>
                <script src="/static/react.production.min.js">
                </script>
            </html>
        """,
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "React"
        for tech in technologies
    )


def test_vue_html_detection():
    result = analyze({
        "headers": {},
        "content": """
            <html>
                <div id="app" data-v-app>
                </div>
                <script src="/js/vue.global.js">
                </script>
            </html>
        """,
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "Vue.js"
        for tech in technologies
    )


def test_angular_html_detection():
    result = analyze({
        "headers": {},
        "content": """
            <html>
                <app-root></app-root>
                <script src="/js/angular.js">
                </script>
            </html>
        """,
    })

    technologies = result["technologies"]

    assert any(
        tech["name"] == "Angular"
        for tech in technologies
    )


def test_multiple_html_technologies():
    result = analyze({
        "headers": {
            "Server": "nginx"
        },
        "content": """
            <html>
                <link
                    href="/wp-content/themes/test/bootstrap.css"
                >
                <script src="/js/jquery.min.js"></script>
            </html>
        """,
    })

    technologies = result["technologies"]

    names = [
        tech["name"]
        for tech in technologies
    ]

    assert "Nginx" in names
    assert "WordPress" in names
    assert "Bootstrap" in names
    assert "jQuery" in names
