from aiohttp import web

import base64
import urllib.parse
import sqlite3
import logging
import os

ACCEPTED_HOSTS = set(['assfixingafistant.github.io'])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('main')

db = sqlite3.connect('links.db')

logger.info(f'Initialising db...')
with db as cur:
  cur.execute('''
    CREATE TABLE IF NOT EXISTS links (
      id INTEGER PRIMARY KEY NOT NULL,
      shortcode BLOB UNIQUE NOT NULL,
      url VARCHAR(2048) UNIQUE NOT NULL,
      ip VARCHAR(40) NOT NULL,
      ts INTEGER DEFAULT (unixepoch()) NOT NULL
    )
  ''')
  cur.execute('''
    CREATE INDEX IF NOT EXISTS links_url ON links(url)
  ''')
  cur.execute('''
    CREATE INDEX IF NOT EXISTS links_shortcode ON links(shortcode)
  ''')


# db methods
def create_shortcode(url: str, ip: str) -> bytes:
  with db as cur:
    existing_row = cur.execute('SELECT shortcode FROM links WHERE url = ?', (url,)).fetchone()
    if existing_row:
      return existing_row[0]

    shortcode = os.urandom(1)
    last_err = None
    for _ in range(128):
      try:
        cur.execute(
          'INSERT INTO links (shortcode, url, ip) VALUES (:shortcode, :url, :ip)',
          {'shortcode': shortcode, 'url': url, 'ip': ip}
        )
      except sqlite3.IntegrityError as e:
        last_err = e
        shortcode += os.urandom(1)
        continue
      return shortcode

  raise RuntimeError('Failed to create shortcode', last_err)


def get_url(shortcode: bytes) -> str | None:
  with db as cur:
    existing_row = cur.execute('SELECT url FROM links WHERE shortcode = ?', (shortcode,)).fetchone()
    if existing_row:
      return existing_row[0]


# shortcode methods
def shortcode_encode(shortcode: bytes):
  return base64.urlsafe_b64encode(shortcode).decode('ascii').rstrip('=')


def shortcode_decode(shortcode_str: str):
  return base64.urlsafe_b64decode(shortcode_str.encode('ascii') + b'==')


# http api
routes = web.RouteTableDef()


@routes.get('/')
async def api_get_root(req: web.Request):
  return web.json_response({':3': 'meow'})


@routes.get('/{shortcode}')
async def api_get_shortcode(req: web.Request):
  try:
    shortcode = shortcode_decode(req.match_info['shortcode'])
  except Exception as e:
    return web.json_response({'error': 'invalid shortcode'}, status=400)
  url = get_url(shortcode)
  if not url:
    return web.json_response({'error': 'unknown shortcode'}, status=404)
  print(req.headers.get('Accept'))
  return web.json_response(
    {'url': url},
    status=302,
    headers={'Location': url}
  )


@routes.post('/create')
async def api_post_create(req: web.Request):
  req_ip = req.headers.get('X-FORWARDED-FOR', None) or req.remote or ''
  try:
    body = await req.json()
  except Exception as e:
    return web.json_response({'error': 'missing request url'}, status=400)

  url = body.get('url')
  if not url:
    return web.json_response({'error': 'missing request url'}, status=400)

  parsed_url = urllib.parse.urlparse(url)
  if parsed_url.hostname not in ACCEPTED_HOSTS:
    return web.json_response({'error': 'hostname not allowed'}, status=400)

  parsed_url = parsed_url._replace(scheme='https')

  shortcode = create_shortcode(parsed_url.geturl(), req_ip)
  return web.json_response({'path': f'/{shortcode_encode(shortcode)}'})


app = web.Application()
app.add_routes(routes)
web.run_app(app, port=9037)