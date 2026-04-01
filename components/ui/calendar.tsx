"use client"

import * as React from "react"
import { ChevronLeft, ChevronRight } from "lucide-react"
import { DayPicker } from "react-day-picker"

import { cn } from "@/lib/utils"

export type CalendarProps = React.ComponentProps<typeof DayPicker>

function Calendar({
  className,
  classNames,
  showOutsideDays = true,
  ...props
}: CalendarProps) {
  return (
    <DayPicker
      showOutsideDays={showOutsideDays}
      className={cn("p-3", className)}

      classNames={{
        months: "flex flex-col sm:flex-row gap-4",
        month: "space-y-4",

        // ✅ FIXED (caption removed in v9)
        caption_label: "text-sm font-medium",

        // ✅ FIXED (nav_button removed in v9)
        nav: "flex items-center justify-between",

        table: "w-full border-collapse",
        head_row: "flex",
        head_cell:
          "text-muted-foreground rounded-md w-9 text-xs font-normal",

        row: "flex w-full mt-2",

        cell: "h-9 w-9 text-center text-sm relative",
        day: "h-9 w-9 flex items-center justify-center text-sm",

        day_selected:
          "bg-primary text-primary-foreground rounded-md",
        day_today: "bg-accent text-accent-foreground rounded-md",
        day_outside: "text-muted-foreground opacity-50",
        day_disabled: "text-muted-foreground opacity-50",

        ...classNames,
      }}

      // ✅ Proper v9 navigation buttons
      components={{
        PreviousMonthButton: (props) => (
          <button {...props}>
            <ChevronLeft className="h-4 w-4" />
          </button>
        ),
        NextMonthButton: (props) => (
          <button {...props}>
            <ChevronRight className="h-4 w-4" />
          </button>
        ),
      }}

      {...props}
    />
  )
}

Calendar.displayName = "Calendar"

export { Calendar }
