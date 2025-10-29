import { type NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'

/**
 * GET /api/copilot/api-keys
 * API keys management endpoint - currently returns empty array after removing sim agent dependency
 */
export async function GET(request: NextRequest) {
  try {
    const session = await getSession()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // API key management is currently disabled (previously managed via sim agent API)
    // Return empty array to maintain client compatibility
    return NextResponse.json({ keys: [] }, { status: 200 })
  } catch (error) {
    return NextResponse.json({ error: 'Failed to get keys' }, { status: 500 })
  }
}

/**
 * DELETE /api/copilot/api-keys
 * API key deletion endpoint - currently a no-op after removing sim agent dependency
 */
export async function DELETE(request: NextRequest) {
  try {
    const session = await getSession()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const url = new URL(request.url)
    const id = url.searchParams.get('id')
    if (!id) {
      return NextResponse.json({ error: 'id is required' }, { status: 400 })
    }

    // API key deletion is currently disabled (previously managed via sim agent API)
    // Return success to maintain client compatibility
    return NextResponse.json({ success: true }, { status: 200 })
  } catch (error) {
    return NextResponse.json({ error: 'Failed to delete key' }, { status: 500 })
  }
}
