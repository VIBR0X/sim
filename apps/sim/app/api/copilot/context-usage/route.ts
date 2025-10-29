import { type NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { getSession } from '@/lib/auth'
import { createLogger } from '@/lib/logs/console/logger'

const logger = createLogger('ContextUsageAPI')

const ContextUsageRequestSchema = z.object({
  chatId: z.string(),
  model: z.string(),
  workflowId: z.string(),
  provider: z.any().optional(),
})

/**
 * POST /api/copilot/context-usage
 * Context usage endpoint - currently returns default values after removing sim agent dependency
 */
export async function POST(req: NextRequest) {
  try {
    logger.info('[Context Usage API] Request received')

    const session = await getSession()
    if (!session?.user?.id) {
      logger.warn('[Context Usage API] No session/user ID')
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await req.json()
    const parsed = ContextUsageRequestSchema.safeParse(body)

    if (!parsed.success) {
      logger.warn('[Context Usage API] Invalid request body', parsed.error.errors)
      return NextResponse.json(
        { error: 'Invalid request body', details: parsed.error.errors },
        { status: 400 }
      )
    }

    // Return default context usage (previously fetched from sim agent API)
    // This is a simplified response to maintain client compatibility
    return NextResponse.json({
      totalTokens: 0,
      maxTokens: 8192,
      contextUsage: 0,
    })
  } catch (error) {
    logger.error('Error fetching context usage:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
