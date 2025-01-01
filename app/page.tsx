import Link from "next/link";

export default function Home() {
  return (
    <div className="h-screen w-screen flex flex-col mt-20 items-center ">
      
      <span className="text-4xl font-medium">Welcome to  <span>OpenAI Playground</span></span>
      <Link href={"/playground"} className="mt-4 text-blue-400 underline"> <span>Test Prompts {"->"}</span></Link>
    </div>
  );
}
