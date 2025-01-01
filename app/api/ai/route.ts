import { AiRequestBody, AiResponse } from "@/app/types";
import { AIMessage, HumanMessage, SystemMessage } from "@langchain/core/messages";
import { ChatOpenAI } from "@langchain/openai";
import { NextRequest, NextResponse } from "next/server";

function getModel(): ChatOpenAI {
    return new ChatOpenAI({
        modelName: "gpt-4o-mini",
        // apiKey: "",
        // azureOpenAIApiDeploymentName: "",
        // azureOpenAIEndpoint: ""
    })
}

async function getModelResponse(prompt: string, query: string):  Promise<string> {
    const model = getModel()
    if(query.length == 0) query = "Hi"
    const messages = [new SystemMessage(prompt), new HumanMessage(query)]
    const aiResponse: AIMessage =  await model.invoke(messages)
    
    return aiResponse.content.toString()
}

export function GET() {
    return Response.json({message: "Hello"})
}

export async function POST(request: NextRequest) {
    const data: AiRequestBody = await request.json()    
    const prompt = data.prompt
    const query = data.query
    const aiResponse: string =  await getModelResponse(prompt, query)
    
    // Make call to oepn ai and send content to client
    return Response.json({
        content: aiResponse
    })
}