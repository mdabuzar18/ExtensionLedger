import os
import zlib
import struct
import math

def make_png(width, height, rgba_data):
    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)
    header = b'\x89PNG\r\n\x1a\n'
    ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type 0
        raw.extend(rgba_data[y*width*4:(y+1)*width*4])
    idat = chunk(b'IDAT', zlib.compress(bytes(raw)))
    iend = chunk(b'IEND', b'')
    return header + ihdr + idat + iend

def draw_shield_icon(size):
    buf = bytearray(size * size * 4)
    cx, cy = size / 2.0, size / 2.0
    r = size * 0.45

    for y in range(size):
        for x in range(size):
            nx = (x - cx) / (size * 0.45)
            ny = (y - cy) / (size * 0.45)
            
            # Shield shape formula
            # Top half is rounded rectangle, bottom tapers to a point
            in_shield = False
            if ny < 0:
                in_shield = (nx*nx + (ny*0.8)**2) <= 1.05 and ny >= -0.85
            else:
                in_shield = abs(nx) <= (1.0 - ny * 0.6) and ny <= 1.05

            idx = (y * size + x) * 4
            if in_shield:
                # Gradient background: deep navy blue to cyan
                t = (y / size)
                r_val = int(14 + 10 * t)
                g_val = int(30 + 100 * t)
                b_val = int(75 + 160 * t)

                # Inner border / highlight
                edge = abs(nx) > (1.0 - (ny if ny > 0 else 0) * 0.6) - 0.12 or ny > 0.9 or ny < -0.75
                if edge:
                    r_val = 0
                    g_val = 220
                    b_val = 255

                # Checkmark in the center
                # Check line from (-0.4, 0.1) to (-0.1, 0.4) to (0.45, -0.3)
                is_check = False
                p1 = (-0.35, 0.05)
                p2 = (-0.05, 0.35)
                p3 = (0.40, -0.25)
                
                # Check segment 1
                dx1, dy1 = p2[0] - p1[0], p2[1] - p1[1]
                t1 = ((nx - p1[0])*dx1 + (ny - p1[1])*dy1) / (dx1*dx1 + dy1*dy1)
                if 0 <= t1 <= 1:
                    d1 = math.hypot(nx - (p1[0] + t1*dx1), ny - (p1[1] + t1*dy1))
                    if d1 < 0.11:
                        is_check = True

                # Check segment 2
                dx2, dy2 = p3[0] - p2[0], p3[1] - p2[1]
                t2 = ((nx - p2[0])*dx2 + (ny - p2[1])*dy2) / (dx2*dx2 + dy2*dy2)
                if 0 <= t2 <= 1:
                    d2 = math.hypot(nx - (p2[0] + t2*dx2), ny - (p2[1] + t2*dy2))
                    if d2 < 0.11:
                        is_check = True

                if is_check:
                    r_val, g_val, b_val = 255, 255, 255

                buf[idx] = r_val
                buf[idx+1] = g_val
                buf[idx+2] = b_val
                buf[idx+3] = 255
            else:
                buf[idx] = 0
                buf[idx+1] = 0
                buf[idx+2] = 0
                buf[idx+3] = 0
    return make_png(size, size, buf)

os.makedirs('icons', exist_ok=True)
for s in [16, 48, 128]:
    png_data = draw_shield_icon(s)
    with open(f'icons/icon-{s}.png', 'wb') as f:
        f.write(png_data)
print("Icons generated successfully!")
