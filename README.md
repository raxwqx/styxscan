# 🕷️ StyxScan

**Hafif HTTP, TLS, DNS ve güvenlik keşif aracı.**

[English documentation](README_EN.md)

StyxScan; güvenlik araştırmacıları, sızma testi uzmanları ve meraklı geliştiriciler için tasarlanmış hafif bir Python aracıdır. Hedefin herkese açık HTTP/HTTPS yanıtlarını, güvenlik başlıklarını, çerezlerini, CORS yapılandırmasını, TLS sertifikasını, DNS kayıtlarını ve `security.txt` dosyasını pasif olarak inceler.

<p>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-14B8A6.svg" />
  <a href="https://github.com/raxwqx/styxscan/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/raxwqx/styxscan/actions/workflows/tests.yml/badge.svg?branch=main" /></a>
</p>

---

## ✨ Özellikler

### 🌐 HTTP / HTTPS

- HTTP durum kodu, nihai URL ve yönlendirme geçmişi
- Sunucu ve `X-Powered-By` bilgisi
- İçerik türü ve yanıt gövdesi boyutu sınırı (varsayılan 512 KB)
- HTTPS'ten HTTP'ye yönlendirme düşüşü tespiti
- Yapılandırılabilir zaman aşımı (varsayılan 10 sn, en fazla 60 sn)

### 🛡️ Güvenlik Analizi

- HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`
- Büyük/küçük harf duyarsız başlık arama
- Zayıf HSTS `max-age`, CSP `unsafe-inline`/`unsafe-eval`, hatalı `X-Content-Type-Options` ve `X-Frame-Options` değerleri için ek bulgular
- Önem dereceli bulgu özeti (CRITICAL / HIGH / MEDIUM / LOW / INFO)

### 🍪 Çerez Analizi

- `Secure`, `HttpOnly`, `SameSite`
- `SameSite=None` ile `Secure` eksikliği
- `__Host-` ve `__Secure-` önek kuralları

### 🔐 TLS İncelemesi

- Önce **sertifika doğrulamalı** el sıkışma
- Süresi dolmuş, kendinden imzalı veya ad uyuşmayan sertifikalarda ayrıntıları göstermek için doğrulamasız yedek el sıkışma
- TLS sürümü, cipher, subject, issuer, seri numarası, SAN
- Geçerlilik başlangıç/bitiş zamanı, kalan gün ve süre dolumu
- Eski TLS sürümü ve zayıf cipher bulguları

### 🌍 DNS Keşfi

- A, AAAA, MX, NS, TXT kayıtları
- SPF: eksik kayıt, çoklu kayıt, `+all` ve `?all` kontrolleri
- DMARC: eksik kayıt, `p=none` ve geçersiz politika kontrolleri
- DNSSEC: alt alan adları için üst bölgeye kadar DNSKEY araması
- Çözümleyici hataları artık sessizce yutulmuyor; NXDOMAIN, zaman aşımı ve ad sunucusu hataları uyarı olarak raporlanıyor

### 📜 security.txt (RFC 9116) — yeni

- `/.well-known/security.txt` ve yedek olarak `/security.txt` keşfi
- `Contact`, `Expires`, `Policy`, `Canonical`, `Preferred-Languages` alanları
- Eksik `Contact`, eksik/geçersiz `Expires` ve süresi dolmuş dosya için bulgular
- Varsayılan olarak açık; `--no-security-txt` ile kapatılabilir

### ↪️ CORS Analizi

- `Access-Control-Allow-Origin` / `-Credentials` / `-Methods` / `-Headers`
- `*` ile kimlik bilgisi kombinasyonu
- `null` origin ve geçersiz origin değerleri
- Belirli origin + kimlik bilgisi durumunda eksik `Vary: Origin`

### 🧬 Teknoloji Tespiti

- Sunucu ve `X-Powered-By` tabanlı tespit
- WordPress, Joomla, Drupal, Next.js, React, Vue.js, Angular, jQuery, Bootstrap, Tailwind CSS, Laravel ve Django
- Yanlış pozitifleri azaltan dar kalıplar; `"value"` içindeki `vue` artık Vue.js sayılmaz
- Tekrarlanan teknoloji kayıtları tekilleştirilir

### 📊 Raporlama

- Rich tabanlı terminal çıktısı
- JSON çıktısı
- Tüm bölümleri içeren HTML raporu
- Terminal ve HTML çıktısında kontrol karakteri temizliği ve HTML kaçışı

---

## 📦 Gereksinimler

- Python 3.10 veya üzeri
- `requests`, `dnspython`, `rich`
- DNS sorguları için sistem çözümleyicisine erişim
- TLS incelemesi için hedefin 443 (veya URL'de belirtilen) portuna TCP erişimi

## 🚀 Kurulum

```bash
git clone https://github.com/raxwqx/styxscan.git
cd styxscan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Windows'ta etkinleştirme:

```powershell
.venv\Scripts\activate
```

Alternatif olarak yalnızca bağımlılıkları kurup modül olarak çalıştırabilirsiniz:

```bash
pip install -r requirements.txt
python -m styxscan example.com
```

## ⚡ Kullanım

Temel tarama:

```bash
styxscan example.com
# veya
python -m styxscan example.com
```

JSON çıktısı:

```bash
styxscan example.com --json
```

HTML raporu:

```bash
styxscan example.com --html report.html
```

JSON ve HTML birlikte:

```bash
styxscan example.com --json --html report.html
```

> Bu durumda JSON standart çıktıya yazılır; HTML kaydetme bilgisi standart hataya gider. Böylece çıktı boru hattında geçerli JSON olarak kalır.

Analizleri kapatma:

```bash
styxscan example.com --no-dns
styxscan example.com --no-tls
styxscan example.com --no-security-txt
```

Zaman aşımı:

```bash
styxscan example.com --timeout 15
```

Yardım ve sürüm:

```bash
styxscan --help
styxscan --version
```

> `http://` hedeflerinde TLS incelemesi otomatik olarak atlanır. `security.txt` keşfi varsayılan olarak açıktır ve hedefe iki ek HTTP isteği yapabilir.

## 🖥️ Örnek çıktı

```text
STYXSCAN v0.2.0
Security Research Toolkit

Target       https://example.com
Status       200
Final URL    https://example.com/
Server       cloudflare

Security Overview

Security Headers    REVIEW      0/6 present
TLS                 VALID       TLSv1.3
DNS Records         OK          5/5 types found
DNS Security        OK          0 finding(s)
security.txt        MISSING     No security.txt found
Cookies             OK          0 detected, 0 finding(s)
CORS                OK          0 finding(s)

Security Summary

CRITICAL    0
HIGH        0
MEDIUM      2
LOW         5
INFO        0
TOTAL       7
```

## 📜 security.txt keşfi

StyxScan önce `https://hedef/.well-known/security.txt`, bulunamazsa `https://hedef/security.txt` adresini ister. RFC 9116 alanları ayrıştırılır ve şu durumlar raporlanır:

| Durum | Önem | Açıklama |
| ----- | ---- | -------- |
| Dosya yok | LOW | İki yol da başarılı yanıt vermedi |
| `Contact` yok | MEDIUM | Güvenlik iletişim adresi tanımlanmamış |
| `Expires` yok | LOW | Zorunlu son kullanma alanı yok |
| `Expires` geçersiz | LOW | ISO 8601 biçiminde değil |
| Süresi dolmuş | MEDIUM | Dosya güncellenmemiş |

Ağ hataları güvenlik bulgusu olarak değil, uyarı olarak raporlanır. `security.txt` içeriği hiçbir zaman komut olarak çalıştırılmaz.

## 📦 JSON çıktısı

JSON çıktısı araç/sürüm bilgisi, HTTP, başlıklar, DNS, TLS, çerezler, CORS, `security_txt`, teknoloji, bulgular ve özet içerir.

```json
{
  "tool": "styxscan",
  "version": "0.2.0",
  "target": "https://example.com",
  "http": {
    "status": 200,
    "url": "https://example.com/",
    "content_type": "text/html; charset=utf-8",
    "content_truncated": false,
    "scheme_downgrade": false
  },
  "tls": {
    "connected": true,
    "verified": true,
    "verification_error": null,
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "days_left": 35,
    "expired": false
  },
  "security_txt": {
    "found": true,
    "url": "https://example.com/.well-known/security.txt",
    "status": 200,
    "contacts": ["mailto:security@example.com"],
    "expires_at": "2027-01-01T00:00:00+00:00",
    "expired": false,
    "valid": true
  },
  "security_summary": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0,
    "total": 0
  }
}
```

Notlar:

- `tls.skipped` yalnızca `--no-tls` kullanıldığında veya hedef `http://` olduğunda `true` olur.
- `security_txt.skipped` yalnızca `--no-security-txt` kullanıldığında `true` olur.
- Ham DNS ve HTTP değerleri JSON'da korunur; terminal ve HTML çıktısında temizlenir/kaçışlanır.

## 🚦 Çıkış kodları

| Kod | Anlam |
| --- | ----- |
| `0` | Tarama tamamlandı (TLS/security.txt bulguları süreci başarısız yapmaz) |
| `1` | HTTP isteği başarısız oldu veya HTML raporu yazılamadı |
| `2` | Geçersiz hedef, zaman aşımı veya komut satırı kullanımı |

## 🛡️ Hedef doğrulama ve sınırlar

- Yalnızca `http://` ve `https://` şemaları kabul edilir; şema yoksa `https://` eklenir.
- URL içindeki kullanıcı adı/parola reddedilir.
- Boşluk, kontrol karakteri, ters bölü, boş etiket, 63 karakterden uzun etiket ve baştaki/sondaki tire reddedilir.
- Hedef alan adı en fazla 253 karakter olabilir.
- Uluslararası alan adları punycode'a çevrilir.
- Port 1–65535 aralığında olmalıdır.
- `--timeout` 0'dan büyük ve en fazla 60 saniye olabilir.
- Yanıt gövdesi varsayılan olarak 512 KB ile sınırlandırılır.
- Yönlendirmeler izlenir; HTTPS'ten HTTP'ye düşüş HIGH bulgu olarak raporlanır.

## 🧪 Testler

Testler canlı ağ erişimi gerektirmez; HTTP, DNS, TLS ve `security.txt` katmanları taklit edilir.

```bash
pip install -e ".[dev]"
python -m pytest -q
```

CI; Linux, macOS ve Windows üzerinde Python 3.10–3.13 sürümleriyle derleme, test ve CLI sürüm kontrolü çalıştırır.

## 📁 Proje yapısı

```text
styxscan/
├── styxscan/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── cookies.py
│   ├── cors.py
│   ├── dns.py
│   ├── findings.py
│   ├── headers.py
│   ├── html_reporter.py
│   ├── http.py
│   ├── reporter.py
│   ├── sanitize.py
│   ├── security_txt.py
│   ├── technology.py
│   └── tls.py
├── tests/
├── .github/workflows/tests.yml
├── CHANGELOG.md
├── LICENSE
├── README.md
├── README_EN.md
├── pyproject.toml
├── requirements.txt
└── styxscan.py
```

## 🧠 Tasarım felsefesi

StyxScan **pasif keşif** odaklıdır. Yalnızca normal HTTP/HTTPS istekleri, DNS sorguları ve TLS el sıkışmaları ile erişilebilen bilgileri toplar. Açık istismar denemesi yapmaz, hedefi değiştirmez ve kimlik doğrulamalı alanlara erişmez.

## ⚠️ Sorumluluk reddi

StyxScan yalnızca **yetkili güvenlik testi, araştırma ve eğitim** amacıyla kullanılmalıdır. Sahibi olmadığınız sistemlere, ağlara veya uygulamalara karşı kullanmayın. Geliştirici, kötüye kullanımdan veya oluşabilecek zarardan sorumlu değildir.

## 📜 Lisans

MIT. Ayrıntılar için [`LICENSE`](LICENSE) dosyasına bakın.
