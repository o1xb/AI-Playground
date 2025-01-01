"use client"

import axios from "axios";
import { useState } from "react";
import { AiResponse } from "../types";

export function UserInput({setAnswer}: {
    setAnswer: (answer: string) => void
}) {

    const [prompt, setPrompt] = useState("")
    const [query, setQuery] = useState("")    
    const [loading, setLoading] = useState(false)

    const buttonClickHandler = async () => {
        setLoading(true)
        setAnswer("")
        try {
            // const res =  await axios.get("https://jsonplaceholder.typicode.com/posts/1")
            const response =  await axios.post("http://localhost:3000/api/ai", {
                prompt,
                query
            })
            const data: AiResponse = response.data
            setAnswer(data.content)
            setLoading(false)

        } catch(e) {
            setAnswer("Error!")
            setLoading(false)
        }
    }

  return (
    <div className="flex flex-col gap-2 p-2 h-full">
      <label htmlFor="prompt">System Prompt</label>
      <textarea
        id="prompt"
        className="border border-gray-500 h-full p-1.5 text-sm"
        rows={4}
        onChange={(e) => setPrompt(e.target.value)}
        value={prompt}
      ></textarea>
      <label htmlFor="query">User Query</label>
      <textarea
        id="query"
        className="border border-gray-500 p-1.5 text-sm"
        rows={4}
        onChange={(e) => setQuery(e.target.value)}
        value={query}
      ></textarea>
      <button className="p-2.5 bg-gray-400 hover:bg-gray-500 rounded-lg" onClick={buttonClickHandler}>
        {loading ? "Loading..." : "Test"}
      </button>
    </div>
  );
}
