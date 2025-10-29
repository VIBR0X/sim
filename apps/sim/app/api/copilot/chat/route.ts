import { db } from '@sim/db'
import { copilotChats } from '@sim/db/schema'
import { and, desc, eq } from 'drizzle-orm'
import { type NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { getSession } from '@/lib/auth'
import {
  authenticateCopilotRequestSessionOnly,
  createBadRequestResponse,
  createInternalServerErrorResponse,
  createRequestTracker,
  createUnauthorizedResponse,
} from '@/lib/copilot/auth'
import { getCopilotModel } from '@/lib/copilot/config'
import type { CopilotProviderConfig } from '@/lib/copilot/types'
import { env } from '@/lib/env'
import { createLogger } from '@/lib/logs/console/logger'
import { generateChatTitle } from '@/lib/sim-agent/utils'
import { createFileContent, isSupportedFileType } from '@/lib/uploads/file-utils'
import { S3_COPILOT_CONFIG } from '@/lib/uploads/setup'
import { downloadFile, getStorageProvider } from '@/lib/uploads/storage-client'
import { v4 } from 'uuid'
import { executeProviderRequest } from '@/providers'
import type { ProviderRequest } from '@/providers/types'

const logger = createLogger('CopilotChatAPI')

const FileAttachmentSchema = z.object({
  id: z.string(),
  key: z.string(),
  filename: z.string(),
  media_type: z.string(),
  size: z.number(),
})

const ChatMessageSchema = z.object({
  message: z.string().min(1, 'Message is required'),
  userMessageId: z.string().optional(), // ID from frontend for the user message
  chatId: z.string().optional(),
  workflowId: z.string().min(1, 'Workflow ID is required'),
  model: z
    .enum([
      'gpt-5-fast',
      'gpt-5',
      'gpt-5-medium',
      'gpt-5-high',
      'gpt-4o',
      'gpt-4.1',
      'o3',
      'claude-4-sonnet',
      'claude-4.5-haiku',
      'claude-4.5-sonnet',
      'claude-4.1-opus',
    ])
    .optional()
    .default('claude-4.5-sonnet'),
  mode: z.enum(['ask', 'agent']).optional().default('agent'),
  prefetch: z.boolean().optional(),
  createNewChat: z.boolean().optional().default(false),
  stream: z.boolean().optional().default(true),
  implicitFeedback: z.string().optional(),
  fileAttachments: z.array(FileAttachmentSchema).optional(),
  provider: z.string().optional().default('openai'),
  conversationId: z.string().optional(),
  contexts: z
    .array(
      z.object({
        kind: z.enum([
          'past_chat',
          'workflow',
          'current_workflow',
          'blocks',
          'logs',
          'workflow_block',
          'knowledge',
          'templates',
          'docs',
        ]),
        label: z.string(),
        chatId: z.string().optional(),
        workflowId: z.string().optional(),
        knowledgeId: z.string().optional(),
        blockId: z.string().optional(),
        templateId: z.string().optional(),
        executionId: z.string().optional(),
        // For workflow_block, provide both workflowId and blockId
      })
    )
    .optional(),
})

/**
 * POST /api/copilot/chat
 * Send messages to sim agent and handle chat persistence
 */
export async function POST(req: NextRequest) {
  const tracker = createRequestTracker()

  try {
    // Get session to access user information including name
    const session = await getSession()

    if (!session?.user?.id) {
      return createUnauthorizedResponse()
    }

    const authenticatedUserId = session.user.id

    const body = await req.json()
    const {
      message,
      userMessageId,
      chatId,
      workflowId,
      model,
      mode,
      prefetch,
      createNewChat,
      stream,
      implicitFeedback,
      fileAttachments,
      provider,
      conversationId,
      contexts,
    } = ChatMessageSchema.parse(body)
    // Ensure we have a consistent user message ID for this request
    const userMessageIdToUse = userMessageId || v4()
    try {
      logger.info(`[${tracker.requestId}] Received chat POST`, {
        hasContexts: Array.isArray(contexts),
        contextsCount: Array.isArray(contexts) ? contexts.length : 0,
        contextsPreview: Array.isArray(contexts)
          ? contexts.map((c: any) => ({
              kind: c?.kind,
              chatId: c?.chatId,
              workflowId: c?.workflowId,
              executionId: (c as any)?.executionId,
              label: c?.label,
            }))
          : undefined,
      })
    } catch {}
    // Preprocess contexts server-side
    let agentContexts: Array<{ type: string; content: string }> = []
    if (Array.isArray(contexts) && contexts.length > 0) {
      try {
        const { processContextsServer } = await import('@/lib/copilot/process-contents')
        const processed = await processContextsServer(contexts as any, authenticatedUserId, message)
        agentContexts = processed
        logger.info(`[${tracker.requestId}] Contexts processed for request`, {
          processedCount: agentContexts.length,
          kinds: agentContexts.map((c) => c.type),
          lengthPreview: agentContexts.map((c) => c.content?.length ?? 0),
        })
        if (Array.isArray(contexts) && contexts.length > 0 && agentContexts.length === 0) {
          logger.warn(
            `[${tracker.requestId}] Contexts provided but none processed. Check executionId for logs contexts.`
          )
        }
      } catch (e) {
        logger.error(`[${tracker.requestId}] Failed to process contexts`, e)
      }
    }

    // Handle chat context
    let currentChat: any = null
    let conversationHistory: any[] = []
    let actualChatId = chatId

    if (chatId) {
      // Load existing chat
      const [chat] = await db
        .select()
        .from(copilotChats)
        .where(and(eq(copilotChats.id, chatId), eq(copilotChats.userId, authenticatedUserId)))
        .limit(1)

      if (chat) {
        currentChat = chat
        conversationHistory = Array.isArray(chat.messages) ? chat.messages : []
      }
    } else if (createNewChat && workflowId) {
      // Create new chat
      const { provider, model } = getCopilotModel('chat')
      const [newChat] = await db
        .insert(copilotChats)
        .values({
          userId: authenticatedUserId,
          workflowId,
          title: null,
          model,
          messages: [],
        })
        .returning()

      if (newChat) {
        currentChat = newChat
        actualChatId = newChat.id
      }
    }

    // Process file attachments if present
    const processedFileContents: any[] = []
    if (fileAttachments && fileAttachments.length > 0) {
      for (const attachment of fileAttachments) {
        try {
          // Check if file type is supported
          if (!isSupportedFileType(attachment.media_type)) {
            logger.warn(`[${tracker.requestId}] Unsupported file type: ${attachment.media_type}`)
            continue
          }

          const storageProvider = getStorageProvider()
          let fileBuffer: Buffer

          if (storageProvider === 's3') {
            fileBuffer = await downloadFile(attachment.key, {
              bucket: S3_COPILOT_CONFIG.bucket,
              region: S3_COPILOT_CONFIG.region,
            })
          } else if (storageProvider === 'blob') {
            const { BLOB_COPILOT_CONFIG } = await import('@/lib/uploads/setup')
            fileBuffer = await downloadFile(attachment.key, {
              containerName: BLOB_COPILOT_CONFIG.containerName,
              accountName: BLOB_COPILOT_CONFIG.accountName,
              accountKey: BLOB_COPILOT_CONFIG.accountKey,
              connectionString: BLOB_COPILOT_CONFIG.connectionString,
            })
          } else {
            fileBuffer = await downloadFile(attachment.key)
          }

          // Convert to format
          const fileContent = createFileContent(fileBuffer, attachment.media_type)
          if (fileContent) {
            processedFileContents.push(fileContent)
          }
        } catch (error) {
          logger.error(
            `[${tracker.requestId}] Failed to process file ${attachment.filename}:`,
            error
          )
          // Continue processing other files
        }
      }
    }

    // Build messages array for sim agent with conversation history
    const messages: any[] = []

    // Add conversation history (need to rebuild these with file support if they had attachments)
    for (const msg of conversationHistory) {
      if (msg.fileAttachments && msg.fileAttachments.length > 0) {
        // This is a message with file attachments - rebuild with content array
        const content: any[] = [{ type: 'text', text: msg.content }]

        // Process file attachments for historical messages
        for (const attachment of msg.fileAttachments) {
          try {
            if (isSupportedFileType(attachment.media_type)) {
              const storageProvider = getStorageProvider()
              let fileBuffer: Buffer

              if (storageProvider === 's3') {
                fileBuffer = await downloadFile(attachment.key, {
                  bucket: S3_COPILOT_CONFIG.bucket,
                  region: S3_COPILOT_CONFIG.region,
                })
              } else if (storageProvider === 'blob') {
                const { BLOB_COPILOT_CONFIG } = await import('@/lib/uploads/setup')
                fileBuffer = await downloadFile(attachment.key, {
                  containerName: BLOB_COPILOT_CONFIG.containerName,
                  accountName: BLOB_COPILOT_CONFIG.accountName,
                  accountKey: BLOB_COPILOT_CONFIG.accountKey,
                  connectionString: BLOB_COPILOT_CONFIG.connectionString,
                })
              } else {
                fileBuffer = await downloadFile(attachment.key)
              }
              const fileContent = createFileContent(fileBuffer, attachment.media_type)
              if (fileContent) {
                content.push(fileContent)
              }
            }
          } catch (error) {
            logger.error(
              `[${tracker.requestId}] Failed to process historical file ${attachment.filename}:`,
              error
            )
          }
        }

        messages.push({
          role: msg.role,
          content,
        })
      } else {
        // Regular text-only message
        messages.push({
          role: msg.role,
          content: msg.content,
        })
      }
    }

    // Add implicit feedback if provided
    if (implicitFeedback) {
      messages.push({
        role: 'system',
        content: implicitFeedback,
      })
    }

    // Add current user message with file attachments
    if (processedFileContents.length > 0) {
      // Message with files - use content array format
      const content: any[] = [{ type: 'text', text: message }]

      // Add file contents
      for (const fileContent of processedFileContents) {
        content.push(fileContent)
      }

      messages.push({
        role: 'user',
        content,
      })
    } else {
      // Text-only message
      messages.push({
        role: 'user',
        content: message,
      })
    }

    const defaults = getCopilotModel('chat')
    const modelToUse = env.COPILOT_MODEL || defaults.model

    let providerConfig: CopilotProviderConfig | undefined
    const providerEnv = env.COPILOT_PROVIDER as any

    if (providerEnv) {
      if (providerEnv === 'azure-openai') {
        providerConfig = {
          provider: 'azure-openai',
          model: modelToUse,
          apiKey: env.AZURE_OPENAI_API_KEY,
          apiVersion: 'preview',
          endpoint: env.AZURE_OPENAI_ENDPOINT,
        }
      } else if (providerEnv === 'google') {
        providerConfig = {
          provider: 'google',
          model: modelToUse,
          apiKey: env.GEMINI_API_KEY,
        }
      } else {
        providerConfig = {
          provider: providerEnv,
          model: modelToUse,
          apiKey: env.GEMINI_API_KEY, // Default to Gemini API key
        }
      }
    } else {
      // Default configuration using Gemini
      providerConfig = {
        provider: 'google',
        model: modelToUse,
        apiKey: env.GEMINI_API_KEY,
      }
    }

    try {
      logger.info(`[${tracker.requestId}] About to call Gemini Provider directly`, {
        hasContext: agentContexts.length > 0,
        contextCount: agentContexts.length,
        hasFileAttachments: processedFileContents.length > 0,
        messageLength: message.length,
        provider: providerConfig?.provider || 'google',
        model: providerConfig?.model || modelToUse,
      })
    } catch {}

    // Check if API key is configured
    if (!providerConfig?.apiKey && !env.GEMINI_API_KEY) {
      logger.error(`[${tracker.requestId}] Gemini API key not configured`)
      return NextResponse.json(
        { error: 'Gemini API key not configured. Please set GEMINI_API_KEY environment variable.' },
        { status: 500 }
      )
    }

    // Build context string from agentContexts if present
    let contextString = ''
    if (agentContexts.length > 0) {
      contextString = agentContexts.map(ctx => `${ctx.type}: ${ctx.content}`).join('\n\n')
    }

    // Prepare system prompt
    const systemPrompt = 'You are a helpful AI assistant for a workflow automation platform. Help users build and debug workflows.'

    // Prepare request for provider
    const providerRequest: ProviderRequest = {
      model: providerConfig?.model || modelToUse,
      apiKey: providerConfig?.apiKey || env.GEMINI_API_KEY,
      systemPrompt: systemPrompt,
      context: contextString || undefined,
      messages: messages.map(msg => ({
        role: msg.role === 'model' ? 'assistant' : msg.role,
        content: typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content),
      })),
      temperature: 0.1,
      maxTokens: 8192,
      stream: stream,
    }

    let providerResponse
    try {
      providerResponse = await executeProviderRequest(
        providerConfig?.provider || 'google',
        providerRequest
      )
    } catch (error) {
      logger.error(`[${tracker.requestId}] Provider execution error:`, {
        error: error instanceof Error ? error.message : String(error),
      })
      return NextResponse.json(
        { error: `Provider error: ${error instanceof Error ? error.message : 'Unknown error'}` },
        { status: 500 }
      )
    }

    // Check if response is a StreamingExecution
    const isStreamingResponse = providerResponse && typeof providerResponse === 'object' && 'stream' in providerResponse && 'execution' in providerResponse

    // If streaming is requested and we got a streaming response
    if (stream && isStreamingResponse) {
      const streamingExecution = providerResponse as any
      // Create user message to save
      const userMessage = {
        id: userMessageIdToUse, // Consistent ID used for request and persistence
        role: 'user',
        content: message,
        timestamp: new Date().toISOString(),
        ...(fileAttachments && fileAttachments.length > 0 && { fileAttachments }),
        ...(Array.isArray(contexts) && contexts.length > 0 && { contexts }),
        ...(Array.isArray(contexts) &&
          contexts.length > 0 && {
            contentBlocks: [{ type: 'contexts', contexts: contexts as any, timestamp: Date.now() }],
          }),
      }

      // Create a pass-through stream that captures the response and converts to SSE format
      const transformedStream = new ReadableStream({
        async start(controller) {
          const encoder = new TextEncoder()
          let assistantContent = ''
          const toolCalls: any[] = []

          // Send chatId as first event
          if (actualChatId) {
            const chatIdEvent = `data: ${JSON.stringify({
              type: 'chat_id',
              chatId: actualChatId,
            })}\n\n`
            controller.enqueue(encoder.encode(chatIdEvent))
            logger.debug(`[${tracker.requestId}] Sent initial chatId event to client`)
          }

          // Start title generation in parallel if needed
          if (actualChatId && !currentChat?.title && conversationHistory.length === 0) {
            generateChatTitle(message)
              .then(async (title) => {
                if (title) {
                  await db
                    .update(copilotChats)
                    .set({
                      title,
                      updatedAt: new Date(),
                    })
                    .where(eq(copilotChats.id, actualChatId!))

                  const titleEvent = `data: ${JSON.stringify({
                    type: 'title_updated',
                    title: title,
                  })}\n\n`
                  controller.enqueue(encoder.encode(titleEvent))
                  logger.info(`[${tracker.requestId}] Generated and saved title: ${title}`)
                }
              })
              .catch((error) => {
                logger.error(`[${tracker.requestId}] Title generation failed:`, error)
              })
          } else {
            logger.debug(`[${tracker.requestId}] Skipping title generation`)
          }

          // Read from provider stream and convert to SSE format
          const reader = streamingExecution.stream.getReader()
          const decoder = new TextDecoder()

          try {
            while (true) {
              const { done, value } = await reader.read()
              if (done) {
                break
              }

              // Decode text chunk from provider
              const textChunk = decoder.decode(value, { stream: true })

              if (textChunk) {
                // Accumulate content
                assistantContent += textChunk

                // Convert to SSE format and send to client
                const contentEvent = `data: ${JSON.stringify({
                  type: 'content',
                  data: textChunk,
                })}\n\n`

                try {
                  controller.enqueue(encoder.encode(contentEvent))
                } catch (enqueueErr) {
                  logger.error(`[${tracker.requestId}] Error enqueueing chunk:`, enqueueErr)
                  reader.cancel()
                  break
                }
              }
            }

            // Send done event
            const doneEvent = `data: ${JSON.stringify({ type: 'done' })}\n\n`
            controller.enqueue(encoder.encode(doneEvent))

            // Log final streaming summary
            logger.info(`[${tracker.requestId}] Streaming complete summary:`, {
              totalContentLength: assistantContent.length,
              hasContent: assistantContent.length > 0,
            })

            // Save messages to database after streaming completes
            if (currentChat) {
              const updatedMessages = [...conversationHistory, userMessage]

              // Save assistant message if there's any content
              if (assistantContent.trim()) {
                const assistantMessage = {
                  id: v4(),
                  role: 'assistant',
                  content: assistantContent,
                  timestamp: new Date().toISOString(),
                }
                updatedMessages.push(assistantMessage)
                logger.info(
                  `[${tracker.requestId}] Saving assistant message with content (${assistantContent.length} chars)`
                )
              } else {
                logger.info(
                  `[${tracker.requestId}] No assistant content to save (aborted before response)`
                )
              }

              // Update chat in database
              await db
                .update(copilotChats)
                .set({
                  messages: updatedMessages,
                  updatedAt: new Date(),
                })
                .where(eq(copilotChats.id, actualChatId!))

              logger.info(`[${tracker.requestId}] Updated chat ${actualChatId} with new messages`, {
                messageCount: updatedMessages.length,
                savedUserMessage: true,
                savedAssistantMessage: assistantContent.trim().length > 0,
              })
            }
          } catch (error) {
            logger.error(`[${tracker.requestId}] Error processing stream:`, error)
            controller.error(error)
          } finally {
            controller.close()
          }
        },
      })

      const response = new Response(transformedStream, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no',
        },
      })

      logger.info(`[${tracker.requestId}] Returning streaming response to client`, {
        duration: tracker.getDuration(),
        chatId: actualChatId,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
        },
      })

      return response
    }

    // For non-streaming responses
    const nonStreamingResponse = providerResponse as any
    const responseContent = nonStreamingResponse.content || ''

    logger.info(`[${tracker.requestId}] Non-streaming response from provider:`, {
      hasContent: !!responseContent,
      contentLength: responseContent.length,
      model: nonStreamingResponse.model,
      hasTokens: !!nonStreamingResponse.tokens,
    })

    // Save messages if we have a chat
    if (currentChat && responseContent) {
      const userMessage = {
        id: userMessageIdToUse, // Consistent ID used for request and persistence
        role: 'user',
        content: message,
        timestamp: new Date().toISOString(),
        ...(fileAttachments && fileAttachments.length > 0 && { fileAttachments }),
        ...(Array.isArray(contexts) && contexts.length > 0 && { contexts }),
        ...(Array.isArray(contexts) &&
          contexts.length > 0 && {
            contentBlocks: [{ type: 'contexts', contexts: contexts as any, timestamp: Date.now() }],
          }),
      }

      const assistantMessage = {
        id: v4(),
        role: 'assistant',
        content: responseContent,
        timestamp: new Date().toISOString(),
      }

      const updatedMessages = [...conversationHistory, userMessage, assistantMessage]

      // Start title generation in parallel if this is first message (non-streaming)
      if (actualChatId && !currentChat.title && conversationHistory.length === 0) {
        logger.info(`[${tracker.requestId}] Starting title generation for non-streaming response`)
        generateChatTitle(message)
          .then(async (title) => {
            if (title) {
              await db
                .update(copilotChats)
                .set({
                  title,
                  updatedAt: new Date(),
                })
                .where(eq(copilotChats.id, actualChatId!))
              logger.info(`[${tracker.requestId}] Generated and saved title: ${title}`)
            }
          })
          .catch((error) => {
            logger.error(`[${tracker.requestId}] Title generation failed:`, error)
          })
      }

      // Update chat in database immediately (without blocking for title)
      await db
        .update(copilotChats)
        .set({
          messages: updatedMessages,
          updatedAt: new Date(),
        })
        .where(eq(copilotChats.id, actualChatId!))
    }

    logger.info(`[${tracker.requestId}] Returning non-streaming response`, {
      duration: tracker.getDuration(),
      chatId: actualChatId,
      responseLength: responseContent.length,
    })

    return NextResponse.json({
      success: true,
      response: {
        content: responseContent,
        model: nonStreamingResponse.model,
        tokens: nonStreamingResponse.tokens,
      },
      chatId: actualChatId,
      metadata: {
        requestId: tracker.requestId,
        message,
        duration: tracker.getDuration(),
      },
    })
  } catch (error) {
    const duration = tracker.getDuration()

    if (error instanceof z.ZodError) {
      logger.error(`[${tracker.requestId}] Validation error:`, {
        duration,
        errors: error.errors,
      })
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      )
    }

    logger.error(`[${tracker.requestId}] Error handling copilot chat:`, {
      duration,
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    })

    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)
    const workflowId = searchParams.get('workflowId')

    if (!workflowId) {
      return createBadRequestResponse('workflowId is required')
    }

    // Get authenticated user using consolidated helper
    const { userId: authenticatedUserId, isAuthenticated } =
      await authenticateCopilotRequestSessionOnly()
    if (!isAuthenticated || !authenticatedUserId) {
      return createUnauthorizedResponse()
    }

    // Fetch chats for this user and workflow
    const chats = await db
      .select({
        id: copilotChats.id,
        title: copilotChats.title,
        model: copilotChats.model,
        messages: copilotChats.messages,
        createdAt: copilotChats.createdAt,
        updatedAt: copilotChats.updatedAt,
      })
      .from(copilotChats)
      .where(
        and(eq(copilotChats.userId, authenticatedUserId), eq(copilotChats.workflowId, workflowId))
      )
      .orderBy(desc(copilotChats.updatedAt))

    // Transform the data to include message count
    const transformedChats = chats.map((chat) => ({
      id: chat.id,
      title: chat.title,
      model: chat.model,
      messages: Array.isArray(chat.messages) ? chat.messages : [],
      messageCount: Array.isArray(chat.messages) ? chat.messages.length : 0,
      previewYaml: null, // Not needed for chat list
      createdAt: chat.createdAt,
      updatedAt: chat.updatedAt,
    }))

    logger.info(`Retrieved ${transformedChats.length} chats for workflow ${workflowId}`)

    return NextResponse.json({
      success: true,
      chats: transformedChats,
    })
  } catch (error) {
    logger.error('Error fetching copilot chats:', error)
    return createInternalServerErrorResponse('Failed to fetch chats')
  }
}
