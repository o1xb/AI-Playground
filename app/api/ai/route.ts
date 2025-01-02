import { AiRequestBody, ClientType } from "@/app/types";
import { AIMessage, HumanMessage, SystemMessage } from "@langchain/core/messages";
import { AzureChatOpenAI, ChatOpenAI } from "@langchain/openai";
import { NextRequest } from "next/server";

function getModel(clientType: ClientType = "Basic"): ChatOpenAI {
    // Client for normal api calls
    switch (clientType) {
        case "Azure":
            return new AzureChatOpenAI({
                model: "gpt-4o",
                deploymentName: process.env.DEPLOYMENT_NAME,
                azureOpenAIEndpoint: process.env.AZURE_OPENAI_ENDPOINT,
                openAIApiVersion: process.env.OPENAI_API_VERSION,
                temperature: 0.7
            });
        case "Basic":
            return new ChatOpenAI({
                modelName: "gpt-4o-mini",
            })
        default:
            return new ChatOpenAI({
                modelName: "gpt-4o-mini",
            })
    }
}

async function getModelResponse(prompt: string, query: string): Promise<string> {
    const clientType: ClientType = process.env.CLIENT_TYPE as ClientType
    const model = getModel(clientType)
    if (query.length == 0) query = "Hi"
    const messages = [new SystemMessage(prompt), new HumanMessage(query)]
    const aiResponse: AIMessage = await model.invoke(messages)

    return aiResponse.content.toString()
}

export function GET() {
    return Response.json({ message: "Hello" })
}

export async function POST(request: NextRequest) {
    const data: AiRequestBody = await request.json()
    const prompt = data.prompt
    const query = data.query
    const aiResponse: string = await getModelResponse(prompt, query)

    // Make call to oepn ai and send content to client
    return Response.json({
        content: aiResponse
    })
}