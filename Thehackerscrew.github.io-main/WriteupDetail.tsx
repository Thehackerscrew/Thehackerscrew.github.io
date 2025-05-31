import React from 'react';
import { useParams } from 'react-router-dom';
import Header from "@/components/Header";
import { Badge } from "@/components/ui/badge";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { 
  faLaptopCode, 
  faScrewdriver, 
  faLock, 
  faGears, 
  faShieldHalved 
} from "@fortawesome/free-solid-svg-icons";

const writeupContent = {
  "jigboy": {
    id: "jigboy",
    title: "Mapna CTF 2024 : JigBoy",
    category: "forensics",
    date: "2024-01-25",
    content: `## Description
> Jigboy, the superhero, possesses the remarkable ability to reel in colossal fish from the depths of the deep blue sea.

JigBoy is one of the forensics challenge from the MAPNA CTF 2024 which ended up getting 5 solves in the CTF and i upsolved it since I couldnt play the CTF on time. 
## Solution
After extracting the file, at the first glance we see a file with \`.damaged\` extension. We can assume its some kind of "Fix the damaged file" challenge so we open it in an hex editor.

![Hex editor view](image.png)

I couldn't figure out what type of damaged file this was so i decided to google the first few hex of the file \`32 0D 0A 1A 0A\` to see if we can get information from the header.
Straight up on the 2nd link it tells that this header belongs to a \`.jbg\` file, more precisely \`.jbg2\` and the correct header is \`97 4A 42 32 0D 0A 1A 0A\`

To understand the Header more:
- \`0x97\`: The first character is nonprintable, so that the file cannot be mistaken for ASCII.
- \`0x4A 0x42 0x32\`: decodes to jb2 
- \`0x1\`: This field indicates that the file uses the sequential organisation, and that the number of pages is known.
- \`0x00 0x00 0x00 0x01\`: This indicates that the file only has 1 page

After fixing the header, I opened the file in STDU viewer but It still gave me an error...

![STDU viewer error](image-1.png)

So there's more than initial file header corrupted so I started reading more about the jb2 format and looking at the changed hex. To understand and to get familiar with the data, I downloaded a sample jbig file and compared the hex

Sample from the Internet:
![Sample hex comparison](image-2.png)

Now I am assuming the size bytes of the file (\`00 30 00 01 00 00 00 01 00 00 01 01 00 00 00 13\`)
has been modified too so I just copied the bytes from the sample to the original file along with the end hex data \`0x00 0x03 0x33 0x00\` to \`0x00 0x03 0x31 0x00\` and tried opening the file and *VOILA* :D We get the flag 

![Flag revealed](image-3.png)

I tried tweaking the size bytes to see what exactly was meant to be changed since I used the same bytes as the sample Image but i ended up either crashing the file or It showing nothing.

> To read more about the JBIG file format: [JBIG Documentation](https://ics.uci.edu/~dan/class/267/papers/jbig2.pdf)
`
  }
};

const getCategoryStyle = (cat: string): { icon: any; color: string } => {
  switch (cat.toLowerCase()) {
    case 'web':
      return {
        icon: faLaptopCode,
        color: 'text-blue-400'
      };
    case 'forensics':
      return {
        icon: faScrewdriver,
        color: 'text-green-400'
      };
    case 'crypto':
      return {
        icon: faLock,
        color: 'text-yellow-400'
      };
    case 'reverse':
      return {
        icon: faGears,
        color: 'text-orange-400'
      };
    case 'misc':
      return {
        icon: faShieldHalved,
        color: 'text-pink-400'
      };
    default:
      return {
        icon: faShieldHalved,
        color: 'text-gray-400'
      };
  }
};

// Table of contents extraction from markdown
const extractTableOfContents = (content: string) => {
  const headings = content.match(/^#{1,6}\s.+$/gm) || [];
  return headings.map((heading, index) => {
    const level = heading.match(/^#{1,6}/)?.[0].length || 1;
    const text = heading.replace(/^#{1,6}\s/, '');
    const id = text.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    return { id, text, level, index };
  });
};

const WriteupDetail = () => {
  const { id } = useParams();
  const writeup = writeupContent[id as keyof typeof writeupContent];
  const tableOfContents = extractTableOfContents(writeup?.content || '');
  const categoryStyle = getCategoryStyle(writeup?.category || '');

  const renderMarkdown = (content: string) => {
    let inCodeBlock = false;
    let codeBlockContent = '';
    let codeBlockLanguage = '';

    return content
      .split('\n')
      .map((line, index) => {
        // Code blocks
        if (line.startsWith('```')) {
          if (!inCodeBlock) {
            // Start of code block
            inCodeBlock = true;
            codeBlockLanguage = line.slice(3).trim();
            codeBlockContent = '';
            return null;
          } else {
            // End of code block
            inCodeBlock = false;
            const content = codeBlockContent;
            codeBlockContent = '';
            return (
              <pre key={index} className="bg-gray-800 border border-gray-700 p-4 rounded-lg my-4">
                <code className="text-sm font-mono text-gray-200">{content}</code>
              </pre>
            );
          }
        }

        if (inCodeBlock) {
          codeBlockContent += line + '\n';
          return null;
        }

        // Headers
        if (line.startsWith('# ')) {
          const text = line.replace('# ', '');
          const id = text.toLowerCase().replace(/[^a-z0-9]+/g, '-');
          return <h1 key={index} id={id} className="text-3xl font-bold text-gray-100 mt-8 mb-4">{text}</h1>;
        }
        if (line.startsWith('## ')) {
          const text = line.replace('## ', '');
          const id = text.toLowerCase().replace(/[^a-z0-9]+/g, '-');
          return <h2 key={index} id={id} className="text-2xl font-semibold text-gray-200 mt-6 mb-3">{text}</h2>;
        }
        if (line.startsWith('### ')) {
          const text = line.replace('### ', '');
          const id = text.toLowerCase().replace(/[^a-z0-9]+/g, '-');
          return <h3 key={index} id={id} className="text-xl font-semibold text-gray-300 mt-5 mb-2">{text}</h3>;
        }

        // Blockquotes
        if (line.startsWith('> ')) {
          return (
            <blockquote key={index} className="border-l-4 border-gray-700 pl-4 my-4 italic text-gray-400">
              {line.slice(2)}
            </blockquote>
          );
        }
        
        // Images
        if (line.startsWith('![')) {
          const match = line.match(/!\[(.*?)\]\((.*?)\)/);
          if (match) {
            const [, alt, src] = match;
            return (
              <div key={index} className="my-4">
                <img 
                  src={`/images/writeups/${id}/${src}`} 
                  alt={alt || ''} 
                  className="max-w-full rounded-lg border border-gray-700"
                />
              </div>
            );
          }
        }
        
        // Lists
        if (line.startsWith('- ')) {
          return <li key={index} className="text-gray-300 ml-4 mb-2">• {line.slice(2)}</li>;
        }
        if (line.match(/^\d+\./)) {
          return <li key={index} className="text-gray-300 ml-4 mb-2">{line}</li>;
        }
        
        // Inline code
        if (line.includes('`')) {
          const parts = line.split('`');
          return (
            <p key={index} className="text-gray-300 leading-relaxed mb-4">
              {parts.map((part, i) => 
                i % 2 === 0 ? 
                  part : 
                  <code key={i} className="bg-gray-800 px-1.5 py-0.5 rounded text-sm font-mono text-gray-200">{part}</code>
              )}
            </p>
          );
        }
        
        // Regular paragraphs
        if (line.trim() && !line.startsWith('`')) {
          return <p key={index} className="text-gray-300 leading-relaxed mb-4">{line}</p>;
        }
        
        return <br key={index} />;
      })
      .filter(Boolean);
  };

  if (!writeup) {
    return (
      <div className="min-h-screen bg-black text-gray-100">
        <Header />
        <div className="max-w-6xl mx-auto px-6 py-8">
          <h1 className="text-3xl font-bold">Writeup not found</h1>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-gray-100">
      <Header />
      
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Table of Contents - Left Sidebar */}
          <div className="lg:col-span-1">
            <div className="sticky top-24 bg-transparent border border-gray-700 rounded-lg p-6">
              <h3 className="font-semibold text-gray-100 mb-4">Table of Contents</h3>
              <nav className="space-y-2">
                {tableOfContents.map((item) => (
                  <a
                    key={item.id}
                    href={`#${item.id}`}
                    className={`block text-sm hover:text-gray-100 transition-colors ${
                      item.level === 1 ? 'font-medium text-gray-100' : 
                      item.level === 2 ? 'text-gray-300 pl-3' : 'text-gray-400 pl-6'
                    }`}
                  >
                    {item.text}
                  </a>
                ))}
              </nav>
            </div>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            <article className="bg-transparent border border-gray-700 rounded-lg p-8">
              {/* Header */}
              <div className="mb-8 pb-6 border-b border-gray-700">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <Badge className="bg-transparent border border-gray-700 hover:bg-transparent px-3 py-1">
                      <FontAwesomeIcon 
                        icon={categoryStyle.icon} 
                        className={`${categoryStyle.color} mr-2 w-4 h-4`}
                      />
                      <span className={categoryStyle.color}>
                        {writeup.category}
                      </span>
                    </Badge>
                  </div>
                  <span className="text-sm text-gray-400">{writeup.date}</span>
                </div>
                <h1 className="text-3xl font-bold text-gray-100">{writeup.title}</h1>
              </div>

              {/* Content */}
              <div className="prose prose-gray max-w-none">
                {renderMarkdown(writeup.content)}
              </div>
            </article>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WriteupDetail; 