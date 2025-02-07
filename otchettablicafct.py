import argparse
import asyncio
import ipaddress
import sys
import socket
from collections import defaultdict
from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
import aiodns

# Фикс для Windows
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

def add_bold_separator(row):
    """Добавляет жирную нижнюю границу для строки"""
    for cell in row.cells:
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        
        tcBorders = OxmlElement('w:tcBorders')
        
        bottom = OxmlElement('w:bottom')
        bottom.set(qn('w:val'), 'single')  # Тип линии
        bottom.set(qn('w:sz'), '12')       # Размер линии (жирная)
        bottom.set(qn('w:space'), '0')     # Отступ
        bottom.set(qn('w:color'), '000000')  # Цвет линии (черный)
        tcBorders.append(bottom)
        
        for border in ['top', 'left', 'right']:
            element = OxmlElement(f'w:{border}')
            element.set(qn('w:val'), 'nil')  # Нет границы
            tcBorders.append(element)
        
        tcPr.append(tcBorders)

def add_separator(row):
    """Добавляет тонкую нижнюю границу для строки"""
    for cell in row.cells:
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        
        tcBorders = OxmlElement('w:tcBorders')
        
        bottom = OxmlElement('w:bottom')
        bottom.set(qn('w:val'), 'single')  # Тип линии
        bottom.set(qn('w:sz'), '3')        # Размер линии (тонкая)
        bottom.set(qn('w:space'), '0')     # Отступ
        bottom.set(qn('w:color'), '000000')  # Цвет линии (черный)
        tcBorders.append(bottom)
        
        for border in ['top', 'left', 'right']:
            element = OxmlElement(f'w:{border}')
            element.set(qn('w:val'), 'nil')  # Нет границы
            tcBorders.append(element)
        
        tcPr.append(tcBorders)

class DNSCache:
    def __init__(self):
        self.forward_cache = defaultdict(list)
        self.reverse_cache = defaultdict(list)
    
    async def resolve_dns(self, host, resolver):
        if host in self.forward_cache:
            return self.forward_cache[host]
        
        try:
            result = await resolver.query(host, 'A')
            ips = [record.host for record in result]
            self.forward_cache[host] = ips
            return ips
        except (aiodns.error.DNSError, Exception):
            return []
    
    async def reverse_dns(self, ip, resolver):
        if ip in self.reverse_cache:
            return self.reverse_cache[ip]
        
        try:
            result = await resolver.query(
                aiodns.reversename.from_address(ip), 
                'PTR'
            )
            names = [record.host.decode() for record in result]
            self.reverse_cache[ip] = names
            return names
        except (aiodns.error.DNSError, Exception):
            return []

def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

async def process_line(line, resolver, cache):
    line = line.strip()
    if not line:
        return []
    
    try:
        if line.count(':') > 1 and '[' in line:
            host, port = line.rsplit(':', 1)
        else:
            host, port = line.split(':', 1) if ':' in line else (line, '')
    except ValueError:
        return []
    
    result = []
    
    if is_ip_address(host):
        hostnames = await cache.reverse_dns(host, resolver)
        if not hostnames:
            result.append({'ip': host, 'dns': '', 'port': port})
        else:
            for name in hostnames:
                result.append({'ip': host, 'dns': name, 'port': port})
    else:
        ips = await cache.resolve_dns(host, resolver)
        if not ips:
            result.append({'ip': '', 'dns': host, 'port': port})
        else:
            for ip in ips:
                result.append({'ip': ip, 'dns': host, 'port': port})
    
    return result

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', required=True, help='Input file with ip:port or dns:port lines')
    args = parser.parse_args()
    
    resolver = aiodns.DNSResolver()
    cache = DNSCache()
    rows = []
    
    try:
        with open(args.f, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Ошибка чтения файла: {str(e)}")
        return
    
    try:
        tasks = [process_line(line, resolver, cache) for line in lines]
        results = await asyncio.gather(*tasks)
        
        for chunk in results:
            rows.extend(chunk)
    except Exception as e:
        print(f"Ошибка обработки данных: {str(e)}")
        return
    
    # Новая группировка данных с уникальными доменами и портами
    ip_order = []
    grouped_data = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    for row in rows:
        if row['ip']:
            ip = row['ip']
            port = row['port']
            dns = row['dns']
            
            if ip not in ip_order:
                ip_order.append(ip)
            
            # Добавляем порт к соответствующему доменному имени
            grouped_data[ip][dns]['ports'].add(port)
    
    # Создание документа
    try:
        document = Document()
        table = document.add_table(rows=0, cols=3)
        
        # Настраиваем стиль таблицы
        tblPr = table._tblPr
        tblBorders = OxmlElement('w:tblBorders')
        for border in ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']:
            element = OxmlElement(f'w:{border}')
            element.set(qn('w:val'), 'nil')
            tblBorders.append(element)
        tblPr.append(tblBorders)
        
        # Заголовки
        row = table.add_row()
        cells = row.cells
        cells[0].text = 'IP-адрес'
        cells[1].text = 'Доменное имя'
        cells[2].text = 'Открытые TCP-порты'
        
        # Добавляем жирную границу после заголовка
        add_bold_separator(row)
        
        # Заполнение данных
        for idx, ip in enumerate(ip_order):
            ip_data = grouped_data[ip]
            domains = sorted(ip_data.keys(), key=lambda x: x or '')
            
            # Определяем первую строку для данного IP
            first_row = True
            
            for domain_idx, domain in enumerate(domains):
                row = table.add_row()  # Создаем новую строку
                cells = row.cells  # Получаем ячейки строки
                
                if first_row:
                    # Если это первая строка для данного IP
                    cells[0].text = ip
                    first_row = False
                else:
                    # Для остальных строк оставляем IP пустым
                    cells[0].text = ''
                
                # Всегда добавляем доменное имя
                cells[1].text = domain if domain else ''
                
                # Объединяем порты через запятую
                ports = ', '.join(sorted(filter(None, ip_data[domain]['ports'])))
                cells[2].text = ports if ports else ''
                
                # Добавляем разделитель только если это последняя строка блока
                if domain_idx == len(domains) - 1:
                    add_separator(row)  # Передаем объект строки
        
        document.save('output.docx')
        print("Файл output.docx успешно создан")
    except Exception as e:
        print(f"Ошибка создания документа: {str(e)}")

if __name__ == '__main__':
    asyncio.run(main())