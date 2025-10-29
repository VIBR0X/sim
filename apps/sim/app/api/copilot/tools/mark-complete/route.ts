import { type NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import {
  authenticateCopilotRequestSessionOnly,
  createBadRequestResponse,
  createRequestTracker,
  createUnauthorizedResponse,
} from '@/lib/copilot/auth'
import { createLogger } from '@/lib/logs/console/logger'

const logger = createLogger('CopilotMarkToolCompleteAPI')

const MarkCompleteSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.number().int(),
  message: z.any().optional(),
  data: z.any().optional(),
})

/**
 * POST /api/copilot/tools/mark-complete
 * Tool completion endpoint - currently a no-op after removing sim agent dependency
 */
export async function POST(req: NextRequest) {
  const tracker = createRequestTracker()

  try {
    const { userId, isAuthenticated } = await authenticateCopilotRequestSessionOnly()
    if (!isAuthenticated || !userId) {
      return createUnauthorizedResponse()
    }

    const body = await req.json()
    const parsed = MarkCompleteSchema.parse(body)

    logger.info(`[${tracker.requestId}] Tool mark-complete received (no-op)`, {
      userId,
      toolCallId: parsed.id,
      toolName: parsed.name,
      status: parsed.status,
    })

    // Tool completion tracking is currently disabled (previously proxied to sim agent API)
    // Return success to avoid breaking client functionality
    return NextResponse.json({ success: true })
  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.warn(`[${tracker.requestId}] Invalid mark-complete request body`, {
        issues: error.issues,
      })
      return createBadRequestResponse('Invalid request body for mark-complete')
    }
    logger.error(`[${tracker.requestId}] Failed to process mark-complete:`, error)
    return NextResponse.json({ success: true }) // Return success anyway to avoid breaking clients
  }
}
