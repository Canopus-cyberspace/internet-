import { create } from "zustand";

export interface SelectedEntityView {
  entityId: string;
  entityType: string;
  fields: Record<string, string>;
  severity?: string;
  source?: string;
  subtitle?: string;
  title: string;
}

interface SelectionStore {
  selectedCaseId: string | null;
  selectedEntity: SelectedEntityView | null;
  selectedGraphEdgeId: string | null;
  selectedGraphNodeId: string | null;
  selectedNetworkEntityId: string | null;
  selectedPluginId: string | null;
  selectedReportId: string | null;
  selectedResponseActionId: string | null;
  selectedResponsePlanId: string | null;
  selectedSettingsSectionId: string | null;
  tableSelections: Record<string, string[]>;
  tableSelectionAnchors: Record<string, string | null>;
  setSelectedCaseId: (selectedCaseId: string | null) => void;
  setSelectedEntity: (selectedEntity: SelectedEntityView | null) => void;
  setSelectedGraphEdgeId: (selectedGraphEdgeId: string | null) => void;
  setSelectedGraphNodeId: (selectedGraphNodeId: string | null) => void;
  setSelectedNetworkEntityId: (selectedNetworkEntityId: string | null) => void;
  setSelectedPluginId: (selectedPluginId: string | null) => void;
  setSelectedReportId: (selectedReportId: string | null) => void;
  setSelectedResponseActionId: (selectedResponseActionId: string | null) => void;
  setSelectedResponsePlanId: (selectedResponsePlanId: string | null) => void;
  setSelectedSettingsSectionId: (selectedSettingsSectionId: string | null) => void;
  setTableSelection: (
    scope: string,
    selectedRowIds: string[],
    anchorRowId?: string | null,
  ) => void;
}

export const useSelectionStore = create<SelectionStore>((set) => ({
  selectedCaseId: null,
  selectedEntity: null,
  selectedGraphEdgeId: null,
  selectedGraphNodeId: null,
  selectedNetworkEntityId: null,
  selectedPluginId: null,
  selectedReportId: null,
  selectedResponseActionId: null,
  selectedResponsePlanId: null,
  selectedSettingsSectionId: null,
  tableSelections: {},
  tableSelectionAnchors: {},
  setSelectedCaseId: (selectedCaseId) => set({ selectedCaseId }),
  setSelectedEntity: (selectedEntity) => set({ selectedEntity }),
  setSelectedGraphEdgeId: (selectedGraphEdgeId) => set({ selectedGraphEdgeId }),
  setSelectedGraphNodeId: (selectedGraphNodeId) => set({ selectedGraphNodeId }),
  setSelectedNetworkEntityId: (selectedNetworkEntityId) =>
    set({ selectedNetworkEntityId }),
  setSelectedPluginId: (selectedPluginId) => set({ selectedPluginId }),
  setSelectedReportId: (selectedReportId) => set({ selectedReportId }),
  setSelectedResponseActionId: (selectedResponseActionId) =>
    set({ selectedResponseActionId }),
  setSelectedResponsePlanId: (selectedResponsePlanId) =>
    set({ selectedResponsePlanId }),
  setSelectedSettingsSectionId: (selectedSettingsSectionId) =>
    set({ selectedSettingsSectionId }),
  setTableSelection: (scope, selectedRowIds, anchorRowId = null) =>
    set((state) => ({
      tableSelections: {
        ...state.tableSelections,
        [scope]: selectedRowIds,
      },
      tableSelectionAnchors: {
        ...state.tableSelectionAnchors,
        [scope]: anchorRowId,
      },
    })),
}));
