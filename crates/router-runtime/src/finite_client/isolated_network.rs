//! Actual kernel namespace checks, never supplied network receipts.
use super::*;

pub(super) struct IsolatedNetwork {
    namespace: File,
    identity: (u64, u64),
}
fn bounded_text(path: &str) -> Result<String> {
    let mut bytes = vec![];
    File::open(path)?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(RuntimeError::Limit);
    }
    String::from_utf8(bytes).map_err(|_| RuntimeError::Sandbox)
}
fn device_names(devices: &str) -> Result<Vec<&str>> {
    let mut lines = devices.lines();
    if !lines.next().is_some_and(|l| l.starts_with("Inter-|"))
        || !lines.next().is_some_and(|l| l.contains("face |"))
    {
        return Err(RuntimeError::Sandbox);
    }
    let mut names = vec![];
    for row in lines.filter(|l| !l.trim().is_empty()) {
        let (name, counters) = row.split_once(':').ok_or(RuntimeError::Sandbox)?;
        let name = name.trim();
        let values: Vec<_> = counters.split_whitespace().collect();
        if name.is_empty()
            || name.len() > 15
            || name.starts_with('.')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || names.contains(&name)
            || values.len() != 16
            || values.iter().any(|n| n.parse::<u64>().is_err())
        {
            return Err(RuntimeError::Sandbox);
        }
        names.push(name);
    }
    if names.is_empty() || names.len() > 64 || !names.contains(&"lo") {
        return Err(RuntimeError::Sandbox);
    }
    Ok(names)
}
fn kernel_view(
    devices: &str,
    routes: &str,
    status: &str,
    kind: &str,
    flags: &BTreeMap<String, u32>,
) -> Result<()> {
    let names = device_names(devices)?;
    if kind.trim() != "772" || flags.len() != names.len() {
        return Err(RuntimeError::Sandbox);
    }
    for name in names {
        let value = *flags.get(name).ok_or(RuntimeError::Sandbox)?;
        if (name == "lo" && value & 9 != 9) || (name != "lo" && value & 0x41 != 0) {
            return Err(RuntimeError::Sandbox);
        }
    }
    let route_rows: Vec<_> = routes.lines().filter(|l| !l.trim().is_empty()).collect();
    if route_rows.len() != 1 || !route_rows[0].starts_with("Iface\tDestination\t") {
        return Err(RuntimeError::Sandbox);
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let values: Vec<_> = status.lines().filter_map(|l| l.strip_prefix(key)).collect();
        if values.len() != 1 || u64::from_str_radix(values[0].trim(), 16) != Ok(0) {
            return Err(RuntimeError::Sandbox);
        }
    }
    let nnp: Vec<_> = status
        .lines()
        .filter_map(|l| l.strip_prefix("NoNewPrivs:"))
        .collect();
    if nnp.len() != 1 || nnp[0].trim() != "1" {
        return Err(RuntimeError::Sandbox);
    }
    Ok(())
}
impl IsolatedNetwork {
    pub(super) fn capture() -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(RuntimeError::Sandbox);
        }
        let namespace = File::open("/proc/thread-self/ns/net")?;
        let meta = namespace.metadata()?;
        let result = Self {
            namespace,
            identity: (meta.dev(), meta.ino()),
        };
        result.check()?;
        Ok(result)
    }
    pub(super) fn identity(&self) -> (u64, u64) {
        self.identity
    }
    pub(super) fn check(&self) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(RuntimeError::Sandbox);
        }
        let current = fs::metadata("/proc/thread-self/ns/net")?;
        let held = self.namespace.metadata()?;
        if (current.dev(), current.ino()) != self.identity
            || (held.dev(), held.ino()) != self.identity
        {
            return Err(RuntimeError::Sandbox);
        }
        let devices = bounded_text("/proc/thread-self/net/dev")?;
        let mut flags = BTreeMap::new();
        for name in device_names(&devices)? {
            let text = bounded_text(&format!("/sys/class/net/{name}/flags"))?;
            let value = u32::from_str_radix(
                text.trim()
                    .strip_prefix("0x")
                    .ok_or(RuntimeError::Sandbox)?,
                16,
            )
            .map_err(|_| RuntimeError::Sandbox)?;
            flags.insert(name.to_owned(), value);
        }
        kernel_view(
            &devices,
            &bounded_text("/proc/thread-self/net/route")?,
            &bounded_text("/proc/thread-self/status")?,
            &bounded_text("/sys/class/net/lo/type")?,
            &flags,
        )
    }
}
pub(super) fn check_listener(listener: &TcpListener) -> Result<()> {
    use rustix::net::sockopt::{socket_reuseaddr, socket_reuseport};
    let address = listener.local_addr()?;
    if address.ip() != IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        || address.port() == 0
        || socket_reuseaddr(listener).map_err(std::io::Error::from)?
        || socket_reuseport(listener).map_err(std::io::Error::from)?
    {
        return Err(RuntimeError::Sandbox);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    const DEV: &str =
        "Inter-| Receive | Transmit\n face |bytes packets\n lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
    const ROUTE: &str = "Iface\tDestination\tGateway\n";
    const STATUS: &str = "CapInh:\t00000000\nCapPrm:\t00000000\nCapEff:\t00000000\nCapBnd:\t00000000\nCapAmb:\t00000000\nNoNewPrivs:\t1\n";
    fn flags() -> BTreeMap<String, u32> {
        [("lo".into(), 9), ("eth0".into(), 1)].into()
    }
    fn inspect(dev: &str, route: &str, status: &str, kind: &str) -> Result<()> {
        let mut flags = flags();
        if !dev.contains("eth0:") {
            flags.remove("eth0");
        }
        kernel_view(dev, route, status, kind, &flags)
    }
    #[test]
    fn network_view_refuses_active_interfaces_routes_caps_and_wrong_device() {
        inspect(DEV, ROUTE, STATUS, "772\n").unwrap();
        for (dev, route, status, kind) in [
            (
                format!("{DEV}eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"),
                ROUTE.into(),
                STATUS.into(),
                "772",
            ),
            (
                DEV.into(),
                format!("{ROUTE}lo\t00000000\t00000000\n"),
                STATUS.into(),
                "772",
            ),
            (
                DEV.into(),
                ROUTE.into(),
                STATUS.replace("CapBnd:\t00000000", "CapBnd:\t00201000"),
                "772",
            ),
            (
                DEV.into(),
                ROUTE.into(),
                STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
                "772",
            ),
            (DEV.into(), ROUTE.into(), STATUS.into(), "1"),
        ] {
            assert!(inspect(&dev, &route, &status, kind).is_err());
        }
    }
    #[test]
    fn down_kernel_fallback_devices_cannot_be_treated_as_active_routes() {
        let devices = format!("{DEV}tunl0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
        let mut flags: BTreeMap<String, u32> = [("lo".into(), 9), ("tunl0".into(), 0x80)].into();
        kernel_view(&devices, ROUTE, STATUS, "772", &flags).unwrap();
        for active in [0x81, 0xc0] {
            flags.insert("tunl0".into(), active);
            assert!(kernel_view(&devices, ROUTE, STATUS, "772", &flags).is_err());
        }
    }
    #[test]
    fn wildcard_reservation_excludes_another_address_even_with_reuse() {
        use rustix::net::sockopt::{set_socket_reuseaddr, set_socket_reuseport};
        use rustix::net::{
            AddressFamily, SocketAddrV4, SocketFlags, SocketType, bind, socket_with,
        };
        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        set_socket_reuseaddr(&listener, false).unwrap();
        set_socket_reuseport(&listener, false).unwrap();
        check_listener(&listener).unwrap();
        let port = listener.local_addr().unwrap().port();
        for reuse in [false, true] {
            let candidate = socket_with(
                AddressFamily::INET,
                SocketType::STREAM,
                SocketFlags::empty(),
                None,
            )
            .unwrap();
            set_socket_reuseaddr(&candidate, reuse).unwrap();
            set_socket_reuseport(&candidate, reuse).unwrap();
            assert!(
                bind(
                    &candidate,
                    &SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), port)
                )
                .is_err()
            );
        }
        set_socket_reuseaddr(&listener, true).unwrap();
        assert!(check_listener(&listener).is_err());
        set_socket_reuseaddr(&listener, false).unwrap();
        set_socket_reuseport(&listener, true).unwrap();
        assert!(check_listener(&listener).is_err());
        assert!(check_listener(&TcpListener::bind(("127.0.0.1", 0)).unwrap()).is_err());
    }
}
