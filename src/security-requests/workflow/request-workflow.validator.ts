import { BadRequestException, Injectable } from '@nestjs/common';
import { RequestStatus } from '@prisma/client';

/**
 * Sentinel SLM — Security Request Workflow Validator
 *
 * Allowed transitions (linear pipeline):
 *   OPEN → SUBMITTED → IN_PROGRESS → PATCHING → REVALIDATION → CLOSED
 *
 * ACTIVE is a secondary flag, not a pipeline step — it overlaps IN_PROGRESS.
 * Backward transitions are blocked. Skipping steps is blocked.
 */
@Injectable()
export class RequestWorkflowValidator {
  /** Ordered pipeline — index determines valid next step */
  private static readonly PIPELINE: RequestStatus[] = [
    RequestStatus.OPEN,
    RequestStatus.SUBMITTED,
    RequestStatus.IN_PROGRESS,
    RequestStatus.PATCHING,
    RequestStatus.REVALIDATION,
    RequestStatus.CLOSED,
  ];

  /** Statuses that allow reopening back to a previous stage (none in MVP) */
  private static readonly TERMINAL: RequestStatus[] = [
    RequestStatus.CLOSED,
  ];

  /**
   * Validate that a status transition is allowed.
   * Throws BadRequestException if blocked.
   */
  validate(current: RequestStatus, next: RequestStatus): void {
    if (current === next) {
      throw new BadRequestException(
        `Request is already in status '${current}'.`,
      );
    }

    if (RequestWorkflowValidator.TERMINAL.includes(current)) {
      throw new BadRequestException(
        `Cannot transition from terminal status '${current}'.`,
      );
    }

    const pipeline = RequestWorkflowValidator.PIPELINE;
    const currentIdx = pipeline.indexOf(current);
    const nextIdx = pipeline.indexOf(next);

    if (currentIdx === -1) {
      throw new BadRequestException(
        `Unknown current status '${current}'.`,
      );
    }

    if (nextIdx === -1) {
      throw new BadRequestException(
        `Unknown target status '${next}'.`,
      );
    }

    // Only allow advancing exactly one step forward
    if (nextIdx !== currentIdx + 1) {
      const allowed = pipeline[currentIdx + 1];
      throw new BadRequestException(
        `Invalid transition: '${current}' → '${next}'. ` +
        `Only '${current}' → '${allowed ?? 'CLOSED'}' is permitted.`,
      );
    }
  }

  /**
   * Return the allowed next status from the current one, or null if terminal.
   */
  nextStatus(current: RequestStatus): RequestStatus | null {
    const pipeline = RequestWorkflowValidator.PIPELINE;
    const idx = pipeline.indexOf(current);
    return idx >= 0 && idx < pipeline.length - 1 ? pipeline[idx + 1] : null;
  }
}
