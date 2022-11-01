package yugaware_client_test

import (
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
)

var _ = Describe("yugaware-client integration tests", func() {
	Context("universe commands", func() {
		When("a universe is created", func() {
			var universe *models.UniverseResp
			BeforeEach(func() {
				err := Provider.ConfigureIfNotExists(ywContext, Options.ProviderName)
				Expect(err).NotTo(HaveOccurred())

				universe = CreateTestUniverseIfNotExists()
			})

			It("can list the universe", func() {
				out, err := ywContext.RunYugawareCommand("universe", "list")
				Expect(err).NotTo(HaveOccurred())

				Expect(string(out)).To(ContainSubstring(string(universe.UniverseUUID)))
				Expect(string(out)).To(ContainSubstring(universe.Name))
				Expect(string(out)).To(ContainSubstring(universe.UniverseDetails.Clusters[0].PlacementInfo.CloudList[0].Code))
				Expect(string(out)).To(ContainSubstring(universe.UniverseDetails.Clusters[0].UserIntent.YbSoftwareVersion))
			})

			It("can get the universe", func() {
				out, err := ywContext.RunYugawareCommand("universe", "get", universe.Name)
				Expect(err).NotTo(HaveOccurred())

				Expect(string(out)).To(ContainSubstring(string(universe.UniverseUUID)))
				Expect(string(out)).To(ContainSubstring(universe.Name))
				Expect(string(out)).To(ContainSubstring(universe.UniverseDetails.Clusters[0].PlacementInfo.CloudList[0].Code))
				Expect(string(out)).To(ContainSubstring(universe.UniverseDetails.Clusters[0].UserIntent.YbSoftwareVersion))

				Expect(string(out)).To(ContainSubstring(universe.UniverseDetails.NodeDetailsSet[0].NodeName))
				Expect(string(out)).To(ContainSubstring(universe.UniverseDetails.NodeDetailsSet[0].CloudInfo.PrivateIP))
				Expect(string(out)).To(ContainSubstring(universe.UniverseDetails.NodeDetailsSet[0].CloudInfo.Az))
				Expect(string(out)).To(ContainSubstring(universe.UniverseDetails.NodeDetailsSet[0].CloudInfo.Region))
			})

			It("can scale the universe up", func() {
				originalUserIntent := universe.UniverseDetails.Clusters[0].UserIntent
				nodeCount := originalUserIntent.NumNodes + 1

				_, err := ywContext.RunYugawareCommand("universe", "scale", universe.Name, "--nodes", strconv.Itoa(int(nodeCount)), "--approve", "--wait")
				Expect(err).NotTo(HaveOccurred())

				expandedUniverse := CreateTestUniverseIfNotExists()
				expandedUserIntent := expandedUniverse.UniverseDetails.Clusters[0].UserIntent

				Expect(expandedUserIntent.NumNodes).To(Equal(nodeCount))
				Expect(expandedUserIntent.UniverseName).To(Equal(originalUserIntent.UniverseName))
				Expect(expandedUserIntent.ReplicationFactor).To(Equal(originalUserIntent.ReplicationFactor))
				Expect(expandedUserIntent.YbSoftwareVersion).To(Equal(originalUserIntent.YbSoftwareVersion))

				Expect(expandedUserIntent.RegionList).To(ContainElements(originalUserIntent.RegionList))

				// TODO: actually set a gflag so that this test makes sense
				for _, gflag := range originalUserIntent.TserverGFlags {
					Expect(expandedUserIntent.TserverGFlags).To(ContainElement(
						gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{gflag: Equal(originalUserIntent.TserverGFlags[gflag])}),
					))
				}

				for _, gflag := range originalUserIntent.MasterGFlags {
					Expect(expandedUserIntent.MasterGFlags).To(ContainElement(
						gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{gflag: Equal(originalUserIntent.TserverGFlags[gflag])}),
					))
				}
			})

			It("can scale the universe down", func() {
				originalUserIntent := universe.UniverseDetails.Clusters[0].UserIntent
				nodeCount := originalUserIntent.NumNodes - 1

				_, err := ywContext.RunYugawareCommand("universe", "scale", universe.Name, "--nodes", strconv.Itoa(int(nodeCount)), "--approve", "--wait")
				Expect(err).NotTo(HaveOccurred())

				expandedUniverse := CreateTestUniverseIfNotExists()
				expandedUserIntent := expandedUniverse.UniverseDetails.Clusters[0].UserIntent

				Expect(expandedUserIntent.NumNodes).To(Equal(nodeCount))
				Expect(expandedUserIntent.UniverseName).To(Equal(originalUserIntent.UniverseName))
				Expect(expandedUserIntent.ReplicationFactor).To(Equal(originalUserIntent.ReplicationFactor))
				Expect(expandedUserIntent.YbSoftwareVersion).To(Equal(originalUserIntent.YbSoftwareVersion))

				Expect(expandedUserIntent.RegionList).To(ContainElements(originalUserIntent.RegionList))

				// TODO: actually set a gflag so that this test makes sense
				for _, gflag := range originalUserIntent.TserverGFlags {
					Expect(expandedUserIntent.TserverGFlags).To(ContainElement(
						gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{gflag: Equal(originalUserIntent.TserverGFlags[gflag])}),
					))
				}

				for _, gflag := range originalUserIntent.MasterGFlags {
					Expect(expandedUserIntent.MasterGFlags).To(ContainElement(
						gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{gflag: Equal(originalUserIntent.TserverGFlags[gflag])}),
					))
				}

			})

			It("can delete the universe", func() {
				_, err := ywContext.RunYugawareCommand("universe", "delete", universe.Name, "--approve", "--delete-backups", "--wait")
				Expect(err).NotTo(HaveOccurred())

				out, err := ywContext.RunYugawareCommand("universe", "list")
				Expect(err).NotTo(HaveOccurred())

				Expect(string(out)).NotTo(ContainSubstring(string(universe.UniverseUUID)))
			})
		})
	})
})
