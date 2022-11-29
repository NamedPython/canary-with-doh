import { rewrite, next } from '@vercel/edge';
import { Options, RequestCookies, ResponseCookies } from '@edge-runtime/cookies';
import { AES, enc } from 'crypto-js'

export const config = {
  matcher: [
    '/'
  ]
}

const canaryLookupTarget = 'canary-lookup.namedpython.dev'
const defaultOptions: Options = { maxAge: 60 * 60 * 24 * 5, sameSite: 'lax', secure: false }

export async function middleware(request: Request) {
  const url = new URL(request.url)
  const cookies = new RequestCookies(request)
  const path = url.pathname
  const isCanaryCookieName = `x-is-canary-${path}`
  const rewritePathCookieName = `x-rewrite-path-${path}`
  const encryptKey = process.env.COOKIES_ENCRYPT_KEY || 'key'
  console.log(encryptKey)
  const { encrypt, decrypt } = AES
  const { Utf8 } = enc

  const rewritePath = decrypt(cookies.get(rewritePathCookieName) || '', encryptKey).toString(Utf8)
  const isCanary = decrypt(cookies.get(isCanaryCookieName) || '', encryptKey).toString(Utf8)
  if (rewritePath) {
    console.log(`cookie for early rewrite found: ${rewritePath}, canary: ${isCanary}`)
    return rewrite(new URL(rewritePath, url))
  }

  try {
    console.time('DNS lookup')
    const canaryLookupResult = await fetch(`https://cloudflare-dns.com/dns-query?name=${canaryLookupTarget}&type=TXT`, {
      headers: {
        'accept': 'application/dns-json'
      }
    })
    console.timeEnd('DNS lookup')

    const data = (await canaryLookupResult.json())?.['Answer']?.[0]?.['data'] as unknown as string
    const rules = data.replace(/"/g, '').split(';').filter(v => v)
    const matched = rules.find((r) => r.startsWith(path))

    const def = matched?.split(' ')
    if (!def || def.length !== 3) {
      return next()
    }

    const [_target, canary, chance] = [def[0], def[1], parseFloat(def[2])]

    const beCanary = routeToCanary(chance)
    const res = beCanary ? rewrite(new URL(canary, url)) : next()
    const resCookies = new ResponseCookies(res)
    if (beCanary) {
      console.log(`route to canary: ${canary}`)
    } else {
      console.log(`route to default: ${path}`)
    }

    // set cookies for early return
    resCookies.set(isCanaryCookieName, encrypt(beCanary ? 'true' : 'false', encryptKey).toString(), defaultOptions)
    resCookies.set(rewritePathCookieName, encrypt(beCanary ? canary : path, encryptKey).toString(), defaultOptions)

    return res
  } catch {
    return next()
  }
}

function routeToCanary(chance: number): boolean {
  const randVal = crypto.getRandomValues(new Uint32Array(1))[0] / (0xffffffff + 1)
  
  console.log(`chance: ${chance}, randVal: ${randVal}`)

  return randVal <= chance
}
