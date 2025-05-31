import Header from "@/components/Header";
import WriteupCard from "@/components/WriteupCard";

// Sample writeup data
const allWriteups = [
  {
    id: "jigboy",
    title: "Mapna CTF 2024 : JigBoy",
  category: "forensics",
    description: "Jigboy, the superhero, possesses the remarkable ability to reel in colossal fish from the depths of the deep blue sea.",
    date: "2024-01-25"
  },
 
];

const Writeups = () => {
  return (
    <div className="min-h-screen bg-black text-gray-100">
      <Header />
      
      <div className="max-w-6xl mx-auto px-6 py-8">
        {/* Page Title */}
        <div className="mb-8">
          <h1 className="text-3xl md:text-4xl font-bold text-gray-100 mb-4">
            Writeups
          </h1>
          <p className="text-lg text-gray-300">
            Detailed guides and walkthroughs for various cybersecurity challenges and topics
          </p>
          </div>

        {/* Writeups Grid */}
        <div className="grid gap-6 md:grid-cols-1 lg:grid-cols-1 max-w-4xl">
          {allWriteups.map((writeup, index) => (
            <WriteupCard
              key={index}
              id={writeup.id}
              title={writeup.title}
              category={writeup.category}
              description={writeup.description}
              date={writeup.date}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

export default Writeups;
