export type AiRequestBody = {
    prompt: string,
    query: string
}

export type AiResponse = {
    content: string
}

export type ClientType = "Basic" | "Azure"