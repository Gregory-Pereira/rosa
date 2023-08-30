package autoscaler

import (
	"os"
	"strings"

	createCluster "github.com/openshift/rosa/cmd/create/cluster"
	"github.com/openshift/rosa/pkg/interactive"
	"github.com/openshift/rosa/pkg/interactive/confirm"
	"github.com/openshift/rosa/pkg/ocm"
	"github.com/openshift/rosa/pkg/rosa"
	"github.com/spf13/cobra"
)

const (
	doubleQuotesToRemove                        = "\"\""
	autoscalerBalanceSimilarNodeGroupsFlag      = "autoscaler-balance-similar-node-groups"
	autoscalerSkipNodesWithLocalStorageFlag     = "autoscaler-skip-nodes-with-local-storage"
	autoscalerLogVerbosityFlag                  = "autoscaler-log-verbosity"
	autoscalerMaxPodGracePeriodFlag             = "autoscaler-max-pod-grace-period"
	autoscalerPodPriorityThresholdFlag          = "autoscaler-pod-priority-threshold"
	autoscalerIgnoreDaemonsetsUtilizationFlag   = "autoscaler-ignore-daemonsets-utilization"
	autoscalerMaxNodeProvisionTimeFlag          = "autoscaler-max-node-provision-time"
	autoscalerBalancingIgnoredLabelsFlag        = "autoscaler-balancing-ignored-labels"
	autoscalerMaxNodesTotalFlag                 = "autoscaler-max-nodes-total"
	autoscalerMinCoresFlag                      = "autoscaler-min-cores"
	autoscalerMaxCoresFlag                      = "autoscaler-max-cores"
	autoscalerMinMemoryFlag                     = "autoscaler-min-memory"
	autoscalerMaxMemoryFlag                     = "autoscaler-max-memory"
	autoscalerScaleDownEnabledFlag              = "autoscaler-scale-down-enabled"
	autoscalerScaleDownUnneededTimeFlag         = "autoscaler-scale-down-unneeded-time"
	autoscalerScaleDownUtilizationThresholdFlag = "autoscaler-scale-down-utilization-threshold"
	autoscalerScaleDownDelayAfterAddFlag        = "autoscaler-scale-down-delay-after-add"
	autoscalerScaleDownDelayAfterDeleteFlag     = "autoscaler-scale-down-delay-after-delete"
	autoscalerScaleDownDelayAfterFailureFlag    = "autoscaler-scale-down-delay-after-failure"
	autoscalerGPULimitsCountFlag                = "autoscaler-gpu-limits-count"
	autoscalerGPULimitsFlag                     = "autoscaler-gpu-limits"
)

var args struct {
	// Autoscaler Configurations
	autoscalerBalanceSimilarNodeGroups    bool
	autoscalerSkipNodesWithLocalStorage   bool
	autoscalerLogVerbosity                int
	autoscalerMaxPodGracePeriod           int
	autoscalerPodPriorityThreshold        int
	autoscalerIgnoreDaemonsetsUtilization bool
	autoscalerMaxNodeProvisionTime        string
	autoscalerBalancingIgnoredLabels      []string
	autoscalerResourceLimits              ResourceLimits
	autoscalerScaleDown                   ScaleDownConfig
}

type ResourceLimits struct {
	MaxNodesTotal       int
	Cores               ResourceRange
	Memory              ResourceRange
	GPULimits           []GPULimit
	GPULimitsInputCount int
}

type GPULimit struct {
	Type string
	Min  int
	Max  int
}

type ResourceRange struct {
	Min int
	Max int
}

type ScaleDownConfig struct {
	Enabled              bool
	UnneededTime         string
	UtilizationThreshold float64
	DelayAfterAdd        string
	DelayAfterDelete     string
	DelayAfterFailure    string
}

var Cmd = &cobra.Command{
	Use:   "autoscaler",
	Short: "Edit autoscaler",
	Long:  "Edit autoscaler for a given cluster.",
	Example: `  # Edit a cluster named "mycluster" to make it private
  rosa edit autoscaler mycluster --private

  # Edit all options interactively
  rosa edit cluster -c mycluster --interactive`,
	Run: run,
}

func init() {
	flags := Cmd.Flags()
	flags.SortFlags = false

	ocm.AddClusterFlag(Cmd)
	confirm.AddFlag(Cmd.Flags())

	// Cluster Autoscaler flags
	flags.BoolVar(
		&args.autoscalerBalanceSimilarNodeGroups,
		autoscalerBalanceSimilarNodeGroupsFlag,
		false,
		"Identify node groups with the same instance type and label set, "+
			"and aim to balance respective sizes of those node groups.",
	)

	flags.BoolVar(
		&args.autoscalerSkipNodesWithLocalStorage,
		autoscalerSkipNodesWithLocalStorageFlag,
		true,
		"If true cluster autoscaler will never delete nodes with pods with local storage, e.g. EmptyDir or HostPat.",
	)

	flags.IntVar(
		&args.autoscalerLogVerbosity,
		autoscalerLogVerbosityFlag,
		1,
		"Autoscaler log level.",
	)

	flags.IntVar(
		&args.autoscalerMaxPodGracePeriod,
		autoscalerMaxPodGracePeriodFlag,
		0,
		"Gives pods graceful termination time before scaling down, measured in seconds.",
	)

	flags.IntVar(
		&args.autoscalerPodPriorityThreshold,
		autoscalerPodPriorityThresholdFlag,
		0,
		"The priority that a pod must exceed to cause the cluster autoscaler to deploy additional nodes. "+
			"Expects an integer, can be negative.",
	)

	flags.BoolVar(
		&args.autoscalerIgnoreDaemonsetsUtilization,
		autoscalerIgnoreDaemonsetsUtilizationFlag,
		false,
		"Should cluster-autoscaler ignore DaemonSet pods when calculating resource utilization for scaling down.",
	)

	flags.StringVar(
		&args.autoscalerMaxNodeProvisionTime,
		autoscalerMaxNodeProvisionTimeFlag,
		"",
		"Maximum time cluster-autoscaler waits for node to be provisioned. "+
			"Expects string comprised of an integer and time unit (ns|us|µs|ms|s|m|h), examples: 20m, 1h.",
	)

	flags.StringSliceVar(
		&args.autoscalerBalancingIgnoredLabels,
		autoscalerBalancingIgnoredLabelsFlag,
		nil,
		"A comma-separated list of label keys that cluster autoscaler should ignore when considering node group similarity.",
	)

	// Resource Limits
	flags.IntVar(
		&args.autoscalerResourceLimits.MaxNodesTotal,
		autoscalerMaxNodesTotalFlag,
		1000,
		"Maximum amount of nodes in the cluster (not only autoscaled ones).",
	)

	flags.IntVar(
		&args.autoscalerResourceLimits.Cores.Min,
		autoscalerMinCoresFlag,
		0,
		"Minimum number of cores to deploy in the cluster.",
	)

	flags.IntVar(
		&args.autoscalerResourceLimits.Cores.Max,
		autoscalerMaxCoresFlag,
		100,
		"Maximum number of cores to deploy in the cluster.",
	)

	flags.IntVar(
		&args.autoscalerResourceLimits.Memory.Min,
		autoscalerMinMemoryFlag,
		0,
		"Minimum amount of memory, in GiB, in the cluster.",
	)

	flags.IntVar(
		&args.autoscalerResourceLimits.Memory.Max,
		autoscalerMaxMemoryFlag,
		4096,
		"Maximum amount of memory, in GiB, in the cluster.",
	)

	flags.IntVar(
		&args.autoscalerResourceLimits.GPULimitsInputCount,
		autoscalerGPULimitsCountFlag,
		0,
		"The number of GPULimitations entries to set later.",
	)

	// Scale down Configuration

	flags.BoolVar(
		&args.autoscalerScaleDown.Enabled,
		autoscalerScaleDownEnabledFlag,
		true,
		"Should Cluster Autoscaler scale down the Cluster.",
	)

	flags.StringVar(
		&args.autoscalerScaleDown.UnneededTime,
		autoscalerScaleDownUnneededTimeFlag,
		"",
		"How long a node should be unneeded before it is eligible for scale down.",
	)

	flags.Float64Var(
		&args.autoscalerScaleDown.UtilizationThreshold,
		autoscalerScaleDownUtilizationThresholdFlag,
		0.5,
		"Node utilization level, defined as sum of requested resources divided by capacity, "+
			"below which a node can be considered for scale down. Value should be between 0 and 1.",
	)

	flags.StringVar(
		&args.autoscalerScaleDown.DelayAfterAdd,
		autoscalerScaleDownDelayAfterAddFlag,
		"",
		"How long after scale up that scale down evaluation resumes.",
	)

	flags.StringVar(
		&args.autoscalerScaleDown.DelayAfterDelete,
		autoscalerScaleDownDelayAfterDeleteFlag,
		"",
		"How long after node deletion that scale down evaluation resumes.",
	)

	flags.StringVar(
		&args.autoscalerScaleDown.DelayAfterFailure,
		autoscalerScaleDownDelayAfterFailureFlag,
		"",
		"How long after scale down failure that scale down evaluation resumes",
	)
}

func run(cmd *cobra.Command, _ []string) {
	r := rosa.NewRuntime().WithAWS().WithOCM()
	defer r.Cleanup()

	clusterKey := r.GetClusterKey()

	if !interactive.Enabled() {
		changedFlags := false
		for _, flag := range []string{autoscalerBalanceSimilarNodeGroupsFlag, autoscalerSkipNodesWithLocalStorageFlag,
			autoscalerLogVerbosityFlag, autoscalerMaxPodGracePeriodFlag,
			autoscalerPodPriorityThresholdFlag, autoscalerIgnoreDaemonsetsUtilizationFlag,
			autoscalerMaxNodeProvisionTimeFlag, autoscalerBalancingIgnoredLabelsFlag,
			autoscalerMaxNodesTotalFlag, autoscalerMinCoresFlag, autoscalerMaxCoresFlag,
			autoscalerMinMemoryFlag, autoscalerMaxMemoryFlag, autoscalerScaleDownEnabledFlag,
			autoscalerScaleDownUnneededTimeFlag, autoscalerScaleDownUtilizationThresholdFlag,
			autoscalerScaleDownDelayAfterAddFlag, autoscalerScaleDownDelayAfterDeleteFlag,
			autoscalerScaleDownDelayAfterFailureFlag, autoscalerGPULimitsCountFlag,
			autoscalerGPULimitsFlag} {
			if cmd.Flags().Changed(flag) {
				changedFlags = true
			}
		}
		if !changedFlags {
			interactive.Enable()
		}
	}

	cluster := r.FetchCluster()

	if interactive.Enabled() {
		r.Reporter.Infof("Interactive mode enabled.\n" +
			"Any optional fields can be ignored and will not be updated.")
	}

	var autoscalerBalanceSimilarNodeGroups *bool
	var autoscalerBalanceSimilarNodeGroupsValue bool
	if cmd.Flags().Changed(autoscalerBalanceSimilarNodeGroupsFlag) {
		autoscalerBalanceSimilarNodeGroupsValue = args.autoscalerBalanceSimilarNodeGroups
		autoscalerBalanceSimilarNodeGroups = &autoscalerBalanceSimilarNodeGroupsValue
	}

	var autoscalerSkipNodesWithLocalStorage *bool
	var autoscalerSkipNodesWithLocalStorageValue bool
	if cmd.Flags().Changed(autoscalerSkipNodesWithLocalStorageFlag) {
		autoscalerSkipNodesWithLocalStorageValue = args.autoscalerSkipNodesWithLocalStorage
		autoscalerSkipNodesWithLocalStorage = &autoscalerSkipNodesWithLocalStorageValue
	}

	var autoscalerLogVerbosity *int
	var autoscalerLogVerbosityValue int
	if cmd.Flags().Changed(autoscalerLogVerbosityFlag) {
		autoscalerLogVerbosityValue = args.autoscalerLogVerbosity
		autoscalerLogVerbosity = &autoscalerLogVerbosityValue
	}

	var autoscalerMaxPodGracePeriod *int
	var autoscalerMaxPodGracePeriodValue int
	if cmd.Flags().Changed(autoscalerMaxPodGracePeriodFlag) {
		autoscalerMaxPodGracePeriodValue = args.autoscalerMaxPodGracePeriod
		autoscalerMaxPodGracePeriod = &autoscalerMaxPodGracePeriodValue
	}

	var autoscalerPodPriorityThreshold *int
	var autoscalerPodPriorityThresholdValue int
	if cmd.Flags().Changed(autoscalerPodPriorityThresholdFlag) {
		autoscalerPodPriorityThresholdValue = args.autoscalerPodPriorityThreshold
		autoscalerPodPriorityThreshold = &autoscalerPodPriorityThresholdValue
	}

	var autoscalerIgnoreDaemonsetsUtilization *bool
	var autoscalerIgnoreDaemonsetsUtilizationValue bool
	if cmd.Flags().Changed(autoscalerIgnoreDaemonsetsUtilizationFlag) {
		autoscalerIgnoreDaemonsetsUtilizationValue = args.autoscalerIgnoreDaemonsetsUtilization
		autoscalerIgnoreDaemonsetsUtilization = &autoscalerIgnoreDaemonsetsUtilizationValue
	}

	var autoscalerMaxNodeProvisionTime *string
	var autoscalerMaxNodeProvisionTimeValue string
	if cmd.Flags().Changed(autoscalerMaxNodeProvisionTimeFlag) {
		autoscalerMaxNodeProvisionTimeValue = args.autoscalerMaxNodeProvisionTime
		autoscalerMaxNodeProvisionTime = &autoscalerMaxNodeProvisionTimeValue
	}

	var autoscalerBalancingIgnoredLabels *[]string
	var autoscalerBalancingIgnoredLabelsValue []string
	if cmd.Flags().Changed(autoscalerBalancingIgnoredLabelsFlag) {
		autoscalerBalancingIgnoredLabelsValue = args.autoscalerBalancingIgnoredLabels
		autoscalerBalancingIgnoredLabels = &autoscalerBalancingIgnoredLabelsValue
	}
	if interactive.Enabled() {
		autoscalerBalancingIgnoredLabelsInput, err := interactive.GetString(interactive.Input{
			Question: "Labels that cluster autoscaler should ignore when considering node group similarity",
			Help:     cmd.Flags().Lookup(autoscalerBalancingIgnoredLabelsFlag).Usage,
			Default:  strings.Join(args.autoscalerBalancingIgnoredLabels, ","),
			Required: false,
			Validators: []interactive.Validator{
				ocm.ValidateBalancingIgnoredLabels,
			},
		})
		if err != nil {
			r.Reporter.Errorf("Expected a valid set of labels for %s: %s", autoscalerBalancingIgnoredLabelsFlag, err)
			os.Exit(1)
		}

		autoscalerBalancingIgnoredLabelsValue = strings.Split(autoscalerBalancingIgnoredLabelsInput, ",")
		autoscalerBalancingIgnoredLabels = &autoscalerBalancingIgnoredLabelsValue
	}

	var maxNodesTotal *int
	var maxNodesTotalValue int
	if cmd.Flags().Changed(autoscalerMaxNodesTotalFlag) {
		maxNodesTotalValue = args.autoscalerResourceLimits.MaxNodesTotal
		maxNodesTotal = &maxNodesTotalValue
	}

	var minMemory *int
	var minMemoryValue int
	if cmd.Flags().Changed(autoscalerMinMemoryFlag) {
		minMemoryValue = args.autoscalerResourceLimits.Memory.Min
		minMemory = &minMemoryValue
	}

	var maxMemory *int
	var maxMemoryValue int
	if cmd.Flags().Changed(autoscalerMaxMemoryFlag) {
		maxMemoryValue = args.autoscalerResourceLimits.Memory.Max
		maxMemory = &maxMemoryValue
	}

	var minCores *int
	var minCoresValue int
	if cmd.Flags().Changed(autoscalerMinCoresFlag) {
		minCoresValue = args.autoscalerResourceLimits.Cores.Min
		minCores = &minCoresValue
	}

	var maxCores *int
	var maxCoresValue int
	if cmd.Flags().Changed(autoscalerMaxCoresFlag) {
		maxCoresValue = args.autoscalerResourceLimits.Cores.Max
		maxCores = &maxCoresValue
	}

	var scaleDownEnabled *bool
	var scaleDownEnabledValue bool
	if cmd.Flags().Changed(autoscalerScaleDownEnabledFlag) {
		scaleDownEnabledValue = args.scaleDownEnabled.scaleDownEnabled
		scaleDownEnabled = &scaleDownEnabledValue
	}

	var scaleDownUnneededTime *string
	var scaleDownUnneededTimeValue string
	if cmd.Flags().Changed(autoscalerScaleDownUnneededTimeFlag) {
		scaleDownEnabledValue = args.autoscalerScaleDown.Enabled
		scaleDownEnabled = &scaleDownEnabledValue
	} else if interactive.Enabled() {
		scaleDownUnneededTimeValue, err := interactive.GetString(interactive.Input{
			Question: "How long a node should be unneeded before it is eligible for scale down",
			Help:     cmd.Flags().Lookup(autoscalerScaleDownUnneededTimeFlag).Usage,
			Default:  scaleDownUnneededTime,
			Required: false,
			Validators: []interactive.Validator{
				createCluster.DurationStringValidator,
			},
		})
		if err != nil {
			r.Reporter.Errorf("Expected a valid value for %s: %s", autoscalerScaleDownUnneededTimeFlag, err)
			os.Exit(1)
		}

		if err := createCluster.DurationStringValidator(scaleDownUnneededTime); err != nil {
			r.Reporter.Errorf("Expected a valid value for %s: %s", autoscalerScaleDownUnneededTimeFlag, err)
			os.Exit(1)
		}
		scaleDownUnneededTime = &scaleDownUnneededTimeValue
	}

	var scaleDownUtilizationThreshold *float64
	var scaleDownUtilizationThresholdValue float64
	if cmd.Flags().Changed(autoscalerScaleDownUtilizationThresholdFlag) {
		scaleDownUtilizationThresholdValue = args.autoscalerScaleDown.UtilizationThreshold
		scaleDownUtilizationThreshold = &scaleDownUtilizationThresholdValue
	}
	if interactive.Enabled() {
		scaleDownUtilizationThresholdValue, err := interactive.GetFloat(interactive.Input{
			Question: "Node utilization level, defined as sum of requested resources divided by capacity, " +
				"below which a node can be considered for scale down",
			Help:     cmd.Flags().Lookup(autoscalerScaleDownUtilizationThresholdFlag).Usage,
			Default:  scaleDownUtilizationThresholdValue,
			Required: false,
			Validators: []interactive.Validator{
				createCluster.ZeroToOneFloatValidator,
			},
		})
		if err != nil {
			r.Reporter.Errorf("Expected a valid value for %s: %s", autoscalerScaleDownUtilizationThresholdFlag, err)
			os.Exit(1)
		}
		if err := createCluster.ZeroToOneFloatValidator(scaleDownUtilizationThresholdValue); err != nil {
			r.Reporter.Errorf("Expected a valid value for %s: %s", autoscalerScaleDownUtilizationThresholdFlag, err)
			os.Exit(1)
		}
		scaleDownUtilizationThreshold = &scaleDownUtilizationThresholdValue
	}

	var scaleDownDelayAfterDelete *string
	var scaleDownDelayAfterDeleteValue string
	if cmd.Flags().Changed(autoscalerScaleDownDelayAfterDeleteFlag) {

	}

	var scaleDownDelayAfterAdd *string
	var scaleDownDelayAfterAddValue string
	if cmd.Flags().Changed(autoscalerScaleDownDelayAfterAddFlag) {

	}

	var scaleDownDelayAfterFailure *string
	var scaleDownDelayAfterFailureValue string
	if cmd.Flags().Changed(autoscalerScaleDownDelayAfterFailureFlag) {

	}
}
