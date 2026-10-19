// Text of the first-run introduction (SRS FR-20.40). Wording follows
// docs/design/writing.md; tools/uilint checks it.
//
// An action names an application control: setup (first-run setup,
// FR-20.8), client-setup (Set Up a Client, FR-20.10) or open-console
// (FR-20.6).

export type IntroAction = "setup" | "client-setup" | "open-console";

export interface IntroStep {
  id: string;
  title: string;
  body: string[];
  tasks?: { title: string; text: string }[];
  note?: string;
  actions?: { action: IntroAction; label: string; unavailable?: string }[];
}

/**
 * Guide topics an introduction step can open in the default browser when
 * the application cannot do the task itself yet. The Rust side maps each to
 * a fixed address (intro_open_guide).
 */
export type GuideTopic = "setup" | "connect";

export const STEPS: readonly IntroStep[] = [
  {
    id: "what",
    title: "What the Gateway does",
    body: [
      "Secure MCP Gateway sits between your AI agents and the tools they use.",
      "Every tool call an agent makes goes through the Gateway. The Gateway checks the call against your policy, records it in the Evidence Journal, and holds a call that needs approval until a person decides.",
    ],
    tasks: [
      { title: "Set up the Gateway", text: "Create its accounts and keys and start it on this Mac." },
      { title: "Connect an agent", text: "Point an agent such as Claude Code at the Gateway." },
      { title: "Review and approve", text: "See what your agents did and decide held calls in the console." },
    ],
    note: "This app does not need an account and sends nothing about your use of it.",
  },
  {
    id: "setup",
    title: "Set up the Gateway",
    body: [
      "Setup asks for two passwords, one for the Administrator account and one for the Approver account, then creates the Gateway's keys and starts the Gateway service.",
      "On a Mac the Gateway runs in the Standalone profile and is labelled not enforced. Policy checks, approvals and the Evidence Journal work, but MCP servers run as ordinary processes, without container or network isolation.",
    ],
    actions: [
      {
        action: "setup",
        label: "Set Up the Gateway",
        unavailable: "This version of the app does not run setup itself yet. The desktop guide lists the two commands to run in Terminal instead.",
      },
    ],
  },
  {
    id: "connect",
    title: "Connect an agent",
    body: [
      "Choose an agent installed on this Mac. Before changing anything, the app shows the exact changes it will make to the agent's settings, and you can remove them later from the same window.",
      "After that, the agent's tool calls go through the Gateway.",
    ],
    actions: [
      {
        action: "client-setup",
        label: "Set Up a Client",
        unavailable: "This version of the app does not connect agents itself yet. The desktop guide shows the command that does it for each supported agent.",
      },
    ],
  },
  {
    id: "review",
    title: "Review and approve",
    body: [
      "The console lists each call your agents made and why the Gateway allowed or refused it. Sign in with the account for the job: Approver to decide held calls, Administrator to change the Gateway.",
      "When a call is waiting for approval, the menu bar shows how many are waiting and macOS shows a notification with the count. A notification never approves a call. You decide in the console.",
    ],
    note: "To read this introduction again, choose Help, then Introduction, in the menu bar menu.",
    actions: [{ action: "open-console", label: "Open Console" }],
  },
];
