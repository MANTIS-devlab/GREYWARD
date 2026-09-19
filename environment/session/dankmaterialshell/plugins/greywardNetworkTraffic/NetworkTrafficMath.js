.pragma library

function normalizedName(value) {
    return String(value || "").trim()
}

function isLoopback(name) {
    const value = normalizedName(name).toLowerCase()
    return value === "lo" || value.startsWith("lo:")
}

// Tunnel and stacked virtual links report bytes in addition to the physical
// link carrying them. They are deliberately excluded from the host aggregate
// unless NetworkManager identifies the link as the active physical device.
function isVirtualOrTunnel(name) {
    const value = normalizedName(name).toLowerCase()
    return value.startsWith("tun") || value.startsWith("tap")
        || value.startsWith("wg") || value.startsWith("ppp")
        || value.startsWith("zt") || value.startsWith("gre")
        || value.startsWith("gretap") || value.startsWith("sit")
        || value.startsWith("vti") || value.startsWith("ip6tnl")
        || value.startsWith("erspan") || value.startsWith("ifb")
        || value.startsWith("br") || value.startsWith("virbr")
        || value.startsWith("docker") || value.startsWith("podman")
        || value.startsWith("veth") || value.startsWith("cni")
        || value.startsWith("flannel") || value.startsWith("cali")
}

function finiteCounter(value) {
    const number = Number(value)
    return Number.isFinite(number) && number >= 0 ? number : null
}

function preferredNames(names) {
    const result = []
    for (const name of names || []) {
        const normalized = normalizedName(name)
        if (normalized && !isLoopback(normalized) && !result.includes(normalized))
            result.push(normalized)
    }
    return result
}

function selectInterfaces(snapshot, preferred) {
    const preferredSet = preferredNames(preferred)
    const selected = []
    for (const entry of snapshot || []) {
        const name = normalizedName(entry?.name || entry?.interface)
        if (!name || isLoopback(name))
            continue
        if (preferredSet.length > 0 ? !preferredSet.includes(name) : isVirtualOrTunnel(name))
            continue
        if (!selected.includes(name))
            selected.push(name)
    }
    return selected
}

function calculateRates(snapshot, previous, elapsedMs, preferred) {
    const entries = snapshot || []
    const previousCounters = previous || {}
    const selected = selectInterfaces(entries, preferred)
    const nextCounters = {}
    let received = 0
    let transmitted = 0
    const elapsed = Number(elapsedMs)

    for (const entry of entries) {
        const name = normalizedName(entry?.name || entry?.interface)
        if (!selected.includes(name) || nextCounters[name])
            continue
        const rx = finiteCounter(entry?.rx ?? entry?.rxtotal)
        const tx = finiteCounter(entry?.tx ?? entry?.txtotal)
        if (rx === null || tx === null)
            continue
        nextCounters[name] = { rx: rx, tx: tx }

        const previousEntry = previousCounters[name]
        if (!previousEntry || !(elapsed > 0))
            continue

        // A negative delta means the interface reset, disappeared and
        // reappeared, or the counter wrapped. Skip only that direction and
        // wait for the next matching sample instead of showing a spike.
        const rxDelta = rx - previousEntry.rx
        const txDelta = tx - previousEntry.tx
        if (rxDelta >= 0)
            received += rxDelta
        if (txDelta >= 0)
            transmitted += txDelta
    }

    return {
        interfaces: selected,
        counters: nextCounters,
        rxRate: elapsed > 0 ? received * 1000 / elapsed : 0,
        txRate: elapsed > 0 ? transmitted * 1000 / elapsed : 0
    }
}

function formatRate(bytesPerSecond) {
    const rate = Number(bytesPerSecond)
    if (!Number.isFinite(rate) || rate < 1024)
        return "0 KB/s"
    if (rate < 1024 * 1024)
        return (rate / 1024).toFixed(rate < 102400 ? 1 : 0) + " KB/s"
    if (rate < 1024 * 1024 * 1024)
        return (rate / (1024 * 1024)).toFixed(rate < 102400 * 1024 ? 1 : 0) + " MB/s"
    return (rate / (1024 * 1024 * 1024)).toFixed(rate < 102400 * 1024 * 1024 ? 1 : 0) + " GB/s"
}
