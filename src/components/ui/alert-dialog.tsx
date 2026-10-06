import * as Dialog from "@radix-ui/react-alert-dialog";
import type { ReactNode } from "react";
import { Button } from "./button";
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  children,
  onConfirm,
  confirm = "Continuer",
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  children: ReactNode;
  onConfirm: () => void;
  confirm?: string;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-slate-950/45 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[min(540px,90vw)] -translate-x-1/2 -translate-y-1/2 rounded-2xl border bg-card p-4 shadow-2xl">
          <Dialog.Title className="mb-3 text-xl font-semibold">
            {title}
          </Dialog.Title>
          <Dialog.Description asChild>
            <div className="text-sm leading-5 text-muted-foreground">
              {children}
            </div>
          </Dialog.Description>
          <div className="mt-3 flex justify-end gap-3">
            <Dialog.Cancel asChild>
              <Button variant="outline">Annuler</Button>
            </Dialog.Cancel>
            <Dialog.Action asChild>
              <Button onClick={onConfirm}>{confirm}</Button>
            </Dialog.Action>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
