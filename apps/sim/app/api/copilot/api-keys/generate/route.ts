import { type NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'

/**
 * POST /api/copilot/api-keys/generate
 * API key generation endpoint - currently disabled after removing sim agent dependency
 */
export async function POST(req: NextRequest) {
  try {
    const session = await getSession()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // API key generation is currently disabled (previously managed via sim agent API)
    return NextResponse.json(
      { error: 'API key generation is currently unavailable' },
      { status: 501 }
    )
  } catch (error) {
    return NextResponse.json({ error: 'Failed to generate copilot API key' }, { status: 500 })
  }
}
