"use client";

import { useState } from "react";
import { Answer } from "../components/Answer";
import { UserInput } from "../components/UserInput";

export default function App() {
  const [answer, setAnswer] = useState("");

  return (
    <>
      <div className="h-screen w-screen flex gap-2 p-2">
        <div className="w-full h-full flex flex-col border border-black">
          <UserInput setAnswer={setAnswer}/>
        </div>
        <div className="w-full h-full border border-black">
          <Answer answer={answer} />
        </div>
      </div>
    </>
  );
}
