FROM nginx:1.27

# Install Python and cron
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    cron \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create output directory linked to nginx html
RUN rm -rf /usr/share/nginx/html \
    && ln -s /app/out /usr/share/nginx/html \
    && mkdir /app/out /app/data

# Install Python dependencies (before copying code for better caching)
RUN pip3 install --break-system-packages --no-cache-dir stem pycryptodomex

# Copy entrypoint scripts (changes less frequently)
COPY entrypoint.sh /entrypoint.sh
COPY run_write_website.sh /app/run_write_website.sh
RUN chmod +x /entrypoint.sh /app/run_write_website.sh

# Copy static assets
COPY out/d3.v4.min.js out/jquery-3.3.1.min.js out/stylesheet-ltr.css out/favicon.ico /app/out/

# Copy Python scripts and config
COPY *.py .
COPY data/consensus.cfg /app/data/

# Run initial website generation
RUN python3 write_website.py

ENTRYPOINT ["/entrypoint.sh"]
