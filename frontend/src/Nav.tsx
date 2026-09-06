export type NavTarget = "upload" | "bulk-upload" | "fleet" | "training";

const LINKS: { target: NavTarget; label: string }[] = [
  { target: "upload", label: "Upload device" },
  { target: "bulk-upload", label: "Bulk upload" },
  { target: "fleet", label: "Fleet dashboard" },
  { target: "training", label: "Vendor training" },
];

export function Nav({
  current,
  onNavigate,
  onLogout,
}: {
  current: NavTarget | null;
  onNavigate: (target: NavTarget) => void;
  onLogout: () => void;
}) {
  return (
    <nav>
      {LINKS.map(({ target, label }) => (
        <button
          key={target}
          onClick={() => onNavigate(target)}
          disabled={current === target}
        >
          {label}
        </button>
      ))}
      <button onClick={onLogout}>Log out</button>
    </nav>
  );
}
