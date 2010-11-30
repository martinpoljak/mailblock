#!/usr/bin/ruby
# encoding: utf-8

require "time"

###

LOG = "./mail.log"
STATUS = "./mailblock.dat"

HOST_MATCHER = /\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/
DAY = 24 * 60 * 60
MEMORY_BACK = 1 * DAY          # one day
BLOCK_UNIT = 2 * DAY           # two days
LIMIT = 90 * DAY               # three months

YESTERDAY = Time.now - MEMORY_BACK

###

def scan_file(seek = 0)
    today = Time.now
    File.open(LOG, "r") do |io|
        io.seek(seek)
        io.each_line do |line|
            begin
                if Time.parse(line[0..14]) < YESTERDAY
                    next
                end
            rescue ArgumentError
                next
            end
            
            if (line.include? "Client host rejected") or (line.include? "blocked using") or (line.include? "Sender address rejected") or (line.include? "too many errors after HELO")
                yield line.match(HOST_MATCHER)[1].to_sym
            end
        end
    end    
end

###

# Loads status
if File.exists? STATUS
    status = Marshal.load(File::read(STATUS))
else
    status = { 
        :logsize => 0,
        :track => { },
        :blocks => [ ]
    }
end

track = status[:track]

# Checks logsize
size = File.size(LOG)
seek = status[:logsize]

if size < status[:logsize]
    status[:logsize] = 0
else
    status[:logsize] = size
end

# Scans file
scan_file(seek) do |ip|
    if not track.include? ip
        track[ip] = [ ]
    end
    
    track[ip] << Time.now
end

# Throws out results older than one day 
#  and sets blocks!
yesterday = Time.now - MEMORY_BACK

remove = [ ]
block = [ ]

track.each_pair do |ip, incidents|
    incidents.reject! { |i| i < yesterday }
    
    if incidents.empty?
        remove << ip
    elsif (incidents.length > 1) and (ip != :"127.0.0.1")
        remove << ip
        block << [ip, incidents.length]
    end
end

remove.each do |ip|
    track.delete(ip)
end

# Cancels expired blocks
status[:blocks].reject! do |ip, data|
    resolution = data[:expiration] < Time.now
    if resolution
        system("iptables -D INPUT -i eth0 -s " << ip.to_s << "/32 -j DROP")
        puts "Unblocking '" << ip.to_s << "'"
    end
    resolution # returns
end

# Blocks hosts for blocking
block.each do |ip, incidents_count|
    length = incidents_count * BLOCK_UNIT
    if length > LIMIT
        length = LIMIT
    end
    
    expiration = Time.now + length
    
    puts "Blocking '" << ip.to_s << "': will expire " << expiration.to_s
    status[:blocks] << [ip, {:start => Time.now, :expiration => expiration}]
    
    system("iptables -I INPUT -i eth0 -s " << ip.to_s << "/32 -j DROP")
end

# Dumps status
File.open(STATUS, "w") do |io|
    Marshal.dump(status, io)
end
    
